"""Activities: every side effect (platform DB writes, external ticket system) lives here."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from temporalio import activity
from temporalio.exceptions import ApplicationError

from spike import platform_db
from spike.models import EffectRequest, EffectResult

# Test hook: if the file named by this env var exists when the ticket has just been created,
# the activity hangs instead of returning, so the test can SIGKILL the worker process
# AFTER the external effect but BEFORE Temporal records the activity as completed.
HANG_ENV = "SPIKE_HANG_AFTER_CREATE_FILE"
# Negative control only: skip the reconcile lookup to show what a naive retry does.
NAIVE_ENV = "SPIKE_NAIVE_NO_RECONCILE"


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def _http(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


@activity.defn
def persist_proposal(workflow_id: str, proposal: dict, db: str) -> str:
    canon = canonical_json(proposal)
    digest = hashlib.sha256(canon.encode()).hexdigest()
    platform_db.save_proposal(db, workflow_id, canon, digest)
    return digest


@activity.defn
def record_workflow_event(workflow_id: str, db: str, event: str, detail: str) -> None:
    platform_db.record_event(db, workflow_id, event, detail)


@activity.defn
def record_operator_resolution(db: str, operation_key: str, ticket_id: str | None, outcome: str) -> None:
    platform_db.record_result(db, operation_key, outcome, ticket_id, activity.info().attempt)


@activity.defn
def execute_ticket_effect(req: EffectRequest) -> EffectResult:
    attempt = activity.info().attempt
    key = req.operation_key
    prior_unresolved = platform_db.unresolved_intents(req.platform_db, key)

    # 1. Intent BEFORE effect.
    platform_db.record_intent(req.platform_db, key, req.workflow_id, req.payload_digest, attempt)
    activity.logger.info("intent recorded key=%s attempt=%d prior_unresolved=%d", key[:12], attempt, prior_unresolved)

    # 2. Reconcile: has a previous (possibly lost-ack) attempt already produced the effect?
    q = urllib.parse.urlencode({"idempotency_key": key})
    if os.environ.get(NAIVE_ENV) == "1":
        status, body = 200, {"tickets": []}  # negative control: pretend nothing exists
    else:
        status, body = _http("GET", f"{req.ticket_url}/tickets?{q}")
    if status == 200 and body["tickets"]:
        tid = body["tickets"][0]["id"]
        platform_db.record_result(req.platform_db, key, "adopted", tid, attempt)
        return EffectResult(ticket_id=tid, outcome="adopted")
    if status == 501 and prior_unresolved > 0:
        # Cannot tell whether the earlier attempt created a ticket. Do NOT blindly retry.
        raise ApplicationError(
            f"{prior_unresolved} earlier attempt(s) have unknown outcome and the external system "
            "cannot be searched by idempotency key",
            type="UncertainEffect",
            non_retryable=True,
        )
    if status not in (200, 501):
        raise RuntimeError(f"lookup failed: HTTP {status} {body}")

    # 3. The effect.
    status, body = _http("POST", f"{req.ticket_url}/tickets", {"idempotency_key": key, "payload": req.proposal})
    if status != 201:
        raise RuntimeError(f"create failed: HTTP {status} {body}")
    tid = body["id"]

    hang = os.environ.get(HANG_ENV)
    if hang and os.path.exists(hang):
        print(f"EFFECT APPLIED ticket={tid}; hanging before ack (attempt {attempt})", flush=True)
        time.sleep(600)  # the test SIGKILLs us here

    # 4. Result AFTER effect.
    platform_db.record_result(req.platform_db, key, "created", tid, attempt)
    return EffectResult(ticket_id=tid, outcome="created")
