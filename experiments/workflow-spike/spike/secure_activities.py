"""Activities for the ids-only workflow. They load everything sensitive from the platform DB.

Configuration comes from the worker process (platform DB path, ticket service URL, effect mode),
never from workflow inputs.

Effect modes (env SPIKE_EFFECT_MODE):
  platform   result-row check + fencing token (effect_claims) + lookup by idempotency key
  naive      no platform idempotency at all: every attempt that reaches the call creates a ticket
Flags:
  SPIKE_HEARTBEAT_GATE=1       before every effect, heartbeat and wait 1.5 s; if the SDK reports the
                               activity cancelled (e.g. not found on the server) skip the effect. This is
                               the best a Temporal-only defence can do (still check-then-act). Implies an
                               interruptible pause.
  SPIKE_PAUSE_INTERRUPTIBLE=1  pause outside the non-interruptible section, so a cancellation from the
                               server is raised into the activity thread while it waits

Test hooks (env, each names a file; the hook is active while the file exists, heartbeating):
  SPIKE_PAUSE_BEFORE_EFFECT_FILE  pause after intent, before the approval re-check and the effect
  SPIKE_HANG_AFTER_CREATE_FILE    pause after the ticket was created, before the result is recorded
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from temporalio import activity
from temporalio.exceptions import ApplicationError

from spike import secure_db as db

PAUSE_ENV = "SPIKE_PAUSE_BEFORE_EFFECT_FILE"
HANG_ENV = "SPIKE_HANG_AFTER_CREATE_FILE"
MODE_ENV = "SPIKE_EFFECT_MODE"
GATE_ENV = "SPIKE_HEARTBEAT_GATE"
INTERRUPTIBLE_ENV = "SPIKE_PAUSE_INTERRUPTIBLE"


def _http(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _wait_while(path: str | None, label: str) -> bool:
    """Heartbeat while `path` exists. Returns True if we paused at all."""
    if not path or not os.path.exists(path):
        return False
    attempt = activity.info().attempt
    _say(f"{label} attempt={attempt} pid={os.getpid()}")
    while os.path.exists(path):
        activity.heartbeat(label)
        time.sleep(0.2)
    return True


class SecureActivities:
    def __init__(self, platform_db: str, ticket_url: str, worker_name: str):
        self.platform_db = platform_db
        self.ticket_url = ticket_url
        self.worker = worker_name or f"{socket.gethostname()}:{os.getpid()}"

    @activity.defn(name="check_proposal")
    def check_proposal(self, tenant_id: str, run_id: str, digest: str) -> str:
        row = db.get_proposal(self.platform_db, tenant_id, run_id)
        if row is None:
            raise ApplicationError("proposal not found", type="ProposalMismatch", non_retryable=True)
        canon, stored = row
        proposal = json.loads(canon)
        if db.digest_of(proposal) != digest or stored != digest:
            raise ApplicationError("proposal digest mismatch", type="ProposalMismatch", non_retryable=True)
        if proposal.get("force_failure"):
            # Realistic leak: exception messages often embed the data being processed.
            raise ApplicationError(f"scanner rejected proposal: {proposal['summary']}",
                                   type="ProposalRejected", non_retryable=True)
        return "ok"

    @activity.defn(name="verify_approval")
    def verify_approval(self, tenant_id: str, run_id: str, digest: str, approval_id: str) -> str:
        return db.approval_verdict(self.platform_db, tenant_id, run_id, digest, approval_id)

    @activity.defn(name="record_event")
    def record_event(self, tenant_id: str, run_id: str, event: str, detail: str) -> None:
        db.record_event(self.platform_db, tenant_id, run_id, event, detail)

    @activity.defn(name="execute_effect")
    def execute_effect(self, tenant_id: str, run_id: str, digest: str, approval_id: str) -> str:
        mode = os.environ.get(MODE_ENV, "platform")  # "platform" | "naive"
        gate = os.environ.get(GATE_ENV) == "1"
        interruptible = gate or os.environ.get(INTERRUPTIBLE_ENV) == "1"
        attempt = activity.info().attempt
        key = db.operation_key(tenant_id, run_id, digest)
        try:
            if mode == "platform":
                prior = db.existing_result(self.platform_db, key)
                if prior:
                    _say(f"attempt={attempt} found recorded result {prior}; adopting")
                    return prior[1]
                db.claim_fence(self.platform_db, key, attempt)
            db.record_intent(self.platform_db, key, tenant_id, run_id, attempt, self.worker)
            activity.heartbeat("intent")

            if interruptible and _wait_while(os.environ.get(PAUSE_ENV), "PRE-EFFECT"):
                # Paused where the SDK may raise CancelledError into this thread.
                _say(f"RESUMED attempt={attempt} is_cancelled={activity.is_cancelled()} "
                     f"details={activity.cancellation_details()}")
            if gate:
                # On EVERY attempt (a frozen worker can be handed a task through its open long-poll and
                # start it only on resume, so "after a pause" is not enough): heartbeat and wait.
                activity.heartbeat("gate")
                time.sleep(1.5)  # give the SDK time to hear back from the server
                _say(f"GATE attempt={attempt} is_cancelled={activity.is_cancelled()} "
                     f"details={activity.cancellation_details()}")

            # From here to the end of the effect is one non-interruptible unit, as a real outbound
            # call is: a cancellation raised into this thread is only delivered after the block.
            # When not `interruptible`, the PRE-EFFECT pause is inside this unit: it models a worker
            # frozen (SIGSTOP, GC pause, VM suspend) at the moment it is about to call out.
            with activity.shield_thread_cancel_exception():
                if not interruptible and _wait_while(os.environ.get(PAUSE_ENV), "PRE-EFFECT"):
                    _say(f"RESUMED attempt={attempt} is_cancelled={activity.is_cancelled()} "
                         f"details={activity.cancellation_details()}")
                if gate and activity.is_cancelled():
                    _say(f"attempt={attempt} SDK reports cancelled; skipping effect")
                    raise ApplicationError("cancelled before effect", type="StaleAttempt", non_retryable=True)
                # Revocation re-check immediately before the effect.
                verdict = db.approval_verdict(self.platform_db, tenant_id, run_id, digest, approval_id)
                if verdict != "valid":
                    _say(f"attempt={attempt} approval re-check verdict={verdict}; no effect")
                    raise ApplicationError(f"approval {verdict}", type="ApprovalRevoked", non_retryable=True)
                if mode == "platform":
                    fence = db.current_fence(self.platform_db, key)
                    if fence != attempt:
                        _say(f"STALE attempt={attempt} fence={fence}; no effect")
                        raise ApplicationError(f"stale attempt {attempt} < fence {fence}",
                                               type="StaleAttempt", non_retryable=True)
                    q = urllib.parse.urlencode({"idempotency_key": key})
                    status, body = _http("GET", f"{self.ticket_url}/tickets?{q}")
                    if status == 200 and body["tickets"]:
                        tid = body["tickets"][0]["id"]
                        db.record_result(self.platform_db, key, "adopted", tid, attempt, self.worker)
                        _say(f"attempt={attempt} adopted existing ticket {tid}")
                        return tid
                canon, _ = db.get_proposal(self.platform_db, tenant_id, run_id)
                status, body = _http("POST", f"{self.ticket_url}/tickets",
                                     {"idempotency_key": key, "payload": json.loads(canon)})
                if status != 201:
                    raise RuntimeError(f"create failed: HTTP {status}")
                tid = body["id"]
                _say(f"EFFECT APPLIED attempt={attempt} ticket={tid} pid={os.getpid()}")

            _wait_while(os.environ.get(HANG_ENV), "HANG-AFTER-CREATE")
            db.record_result(self.platform_db, key, "created", tid, attempt, self.worker)
            _say(f"ACTIVITY RETURNING attempt={attempt} ticket={tid}")
            return tid
        except BaseException as e:  # log what the activity observed, then propagate unchanged
            _say(f"ACTIVITY EXIT attempt={attempt} {type(e).__name__}: {e} "
                 f"details={activity.cancellation_details()}")
            if type(e).__name__ == "CancelledError":
                db.record_event(self.platform_db, tenant_id, run_id, "activity_observed_cancel",
                                f"attempt={attempt} details={activity.cancellation_details()}")
            raise
