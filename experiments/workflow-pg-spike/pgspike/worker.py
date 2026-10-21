"""Worker process: claims due runs from PostgreSQL and drives them one step at a time.

    WFSPIKE_DSN=... python -m pgspike.worker --name w1 --ticket-url http://127.0.0.1:8099
        [--handler-versions 1,2] [--lease-ttl 3] [--poll 0.2] [--backoff-base 0.5] [--backoff-cap 5]

Every state change happens in a transaction that first locks this run's lease row and checks that
the lease is live, owned by this worker and carries this worker's fencing token. A stale worker
therefore cannot change anything. The external call itself happens outside any transaction; the
fake service receives the fencing token and idempotency key for defence in depth.

Test-only hooks (environment variables, each names a file; the hook fires only while it exists):
  WFSPIKE_PAUSE_BEFORE_GATE_FILE    print a marker and wait (until the file is removed) before the gate
  WFSPIKE_PAUSE_AFTER_PREPARE_FILE  ... after the gate committed the 'prepared' intent
  WFSPIKE_PAUSE_BEFORE_EFFECT_FILE  ... after the intent is 'executing', right before the HTTP call
  WFSPIKE_HANG_AFTER_EFFECT_FILE    hang forever after the ticket was created (the test SIGKILLs us)
  WFSPIKE_NO_RECONCILE=1            negative control: never look up the external system
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from pgspike.api import operation_key


class Fenced(Exception):
    """This worker no longer holds the run (lease expired or another worker claimed it)."""


def http(method: str, url: str, body: dict | None = None, timeout: float = 5) -> tuple[int | None, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except OSError as e:  # connection refused/reset, timeout: outcome of a POST is unknown
        return None, {"error": f"{type(e).__name__}: {e}"}


# ---- handlers (versioned business logic for kind=open_remediation_ticket) ------------------------
class HandlerV1:
    version = 1

    @staticmethod
    def request(run: dict, key: str, token: int) -> dict:
        return {"idempotency_key": key, "fencing_token": token, "payload": run["proposal"]}


class HandlerV2:
    version = 2

    @staticmethod
    def request(run: dict, key: str, token: int) -> dict:
        return {"idempotency_key": key, "fencing_token": token, "payload": run["proposal"],
                "meta": {"handler_version": 2, "labels": ["axiom-remediation"]}}


HANDLERS = {1: HandlerV1, 2: HandlerV2}

CANDIDATE_SQL = """
SELECT r.id, r.tenant_id
FROM wf.workflow_runs r JOIN wf.job_leases l ON l.run_id = r.id
WHERE r.due_at <= now()
  AND r.state IN ('awaiting_approval', 'ready', 'retry_wait', 'executing')
  AND (l.lease_expires_at IS NULL OR l.lease_expires_at <= now())
  AND r.handler_version = ANY(%(versions)s::int[])
  AND NOT (r.tenant_id = ANY(%(excluded)s::text[]))
ORDER BY r.due_at, r.created_at
LIMIT 1
FOR UPDATE OF l SKIP LOCKED
"""


class Worker:
    def __init__(self, dsn: str, name: str, ticket_url: str, versions: list[int], lease_ttl: float,
                 poll: float, backoff_base: float, backoff_cap: float):
        self.name, self.ticket_url, self.versions = name, ticket_url, versions
        self.lease_ttl, self.poll = lease_ttl, poll
        self.backoff_base, self.backoff_cap = backoff_base, backoff_cap
        self.pool = ConnectionPool(dsn, min_size=2, max_size=3, kwargs={"row_factory": dict_row},
                                   check=ConnectionPool.check_connection, open=True, name=name)
        self.current: tuple | None = None  # (run_id, token) being worked on, for the heartbeat
        self.no_reconcile = os.environ.get("WFSPIKE_NO_RECONCILE") == "1"
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def log(self, msg: str) -> None:
        t = time.time()
        print(f"[{time.strftime('%H:%M:%S', time.localtime(t))}.{int(t * 1000) % 1000:03d}] {self.name}: {msg}",
              flush=True)

    # ---- hooks ---------------------------------------------------------------------------------
    def hook(self, env: str, run_id, token: int) -> None:
        path = os.environ.get(env)
        if not path or not os.path.exists(path):
            return
        if env == "WFSPIKE_HANG_AFTER_EFFECT_FILE":
            self.log(f"HOOK {env}: effect applied for run={run_id} token={token}; hanging before recording result")
            time.sleep(3600)
        self.log(f"HOOK {env}: paused run={run_id} token={token}")
        while os.path.exists(path):
            time.sleep(0.05)
        self.log(f"HOOK {env}: resumed run={run_id} token={token}")

    # ---- leases --------------------------------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        while True:
            time.sleep(self.lease_ttl / 3)
            cur = self.current
            if not cur:
                continue
            try:
                with self.pool.connection() as conn:
                    n = conn.execute(
                        "UPDATE wf.job_leases SET lease_expires_at = now() + make_interval(secs => %s)"
                        " WHERE run_id=%s AND fencing_token=%s AND lease_owner=%s",
                        (self.lease_ttl, cur[0], cur[1], self.name)).rowcount
                if n == 0 and self.current == cur:
                    self.log(f"heartbeat: lease on run={cur[0]} token={cur[1]} is gone")
            except Exception as e:  # noqa: BLE001
                self.log(f"heartbeat error: {type(e).__name__}: {e}")

    def lock_lease(self, cur, run_id, token: int) -> None:
        cur.execute("SELECT lease_owner, fencing_token, coalesce(lease_expires_at > now(), false) AS live"
                    " FROM wf.job_leases WHERE run_id=%s FOR UPDATE", (run_id,))
        l = cur.fetchone()
        if l["fencing_token"] != token or l["lease_owner"] != self.name or not l["live"]:
            raise Fenced(f"run={run_id} my token={token}, current token={l['fencing_token']} "
                         f"owner={l['lease_owner']} live={l['live']}")

    def release(self, cur, run_id, token: int) -> None:
        cur.execute("UPDATE wf.job_leases SET lease_owner=NULL, lease_expires_at=NULL"
                    " WHERE run_id=%s AND fencing_token=%s", (run_id, token))

    def event(self, cur, run_id, event: str, detail: str, token: int | None) -> None:
        cur.execute("INSERT INTO wf.run_events (run_id, event, detail, worker, fencing_token) VALUES (%s,%s,%s,%s,%s)",
                    (run_id, event, detail, self.name, token))

    def claim(self) -> tuple[dict, int] | None:
        excluded: list[str] = []
        for _ in range(50):
            with self.pool.connection() as conn, conn.cursor() as cur:
                cur.execute(CANDIDATE_SQL, {"versions": self.versions, "excluded": excluded})
                cand = cur.fetchone()
                if cand is None:
                    return None
                # Serialise claims per tenant, then count live leases with a fresh statement
                # (READ COMMITTED: sees claims committed while we waited for the lock).
                cur.execute("SELECT max_concurrent FROM wf.tenant_limits WHERE tenant_id=%s FOR UPDATE",
                            (cand["tenant_id"],))
                limit = cur.fetchone()["max_concurrent"]
                cur.execute("SELECT count(*) AS n FROM wf.job_leases l JOIN wf.workflow_runs r ON r.id = l.run_id"
                            " WHERE r.tenant_id=%s AND l.lease_expires_at > now()", (cand["tenant_id"],))
                if cur.fetchone()["n"] >= limit:
                    conn.rollback()
                    excluded.append(cand["tenant_id"])
                    continue
                cur.execute(
                    "UPDATE wf.job_leases SET lease_owner=%s, lease_expires_at = now() + make_interval(secs => %s),"
                    " fencing_token = fencing_token + 1 WHERE run_id=%s RETURNING fencing_token",
                    (self.name, self.lease_ttl, cand["id"]))
                token = cur.fetchone()["fencing_token"]
                cur.execute("SELECT * FROM wf.workflow_runs WHERE id=%s", (cand["id"],))
                run = cur.fetchone()
                self.event(cur, run["id"], "claimed", f"state={run['state']} attempts={run['attempts']}", token)
                return run, token
        return None

    # ---- terminal / parking helpers (caller holds the lease lock) -----------------------------
    def finish(self, cur, run, token: int, state: str, detail: str, event: str | None = None) -> None:
        cur.execute("UPDATE wf.workflow_runs SET state=%s, step='done', due_at=NULL, detail=%s, version=version+1,"
                    " updated_at=clock_timestamp(), finished_at=clock_timestamp() WHERE id=%s",
                    (state, detail, run["id"]))
        self.release(cur, run["id"], token)
        self.event(cur, run["id"], event or state, detail, token)
        self.log(f"run={run['id']} -> {state}: {detail}")

    def park_for_operator(self, cur, run, token: int, detail: str) -> None:
        cur.execute("UPDATE wf.workflow_runs SET state='needs_operator_reconciliation', step='operator', due_at=NULL,"
                    " detail=%s, version=version+1, updated_at=clock_timestamp() WHERE id=%s", (detail, run["id"]))
        self.release(cur, run["id"], token)
        self.event(cur, run["id"], "needs_operator_reconciliation", detail, token)
        self.log(f"run={run['id']} -> needs_operator_reconciliation: {detail}")

    # ---- the state machine ---------------------------------------------------------------------
    def process(self, run: dict, token: int) -> None:
        key = operation_key(run["id"], run["proposal_digest"])
        with self.pool.connection() as conn:
            intent = conn.execute("SELECT * FROM wf.execution_intents WHERE operation_key=%s", (key,)).fetchone()

        if run["state"] == "awaiting_approval" and not run["reconcile_required"]:
            # Only claimable once due_at (= approval deadline) has passed: the deadline timer fired.
            with self.pool.connection() as conn, conn.cursor() as cur:
                self.lock_lease(cur, run["id"], token)
                cur.execute("SELECT state FROM wf.workflow_runs WHERE id=%s FOR UPDATE", (run["id"],))
                if cur.fetchone()["state"] == "awaiting_approval":
                    self.finish(cur, run, token, "approval_expired", "approval deadline passed without approval",
                                "approval_deadline_timer_fired")
            return

        uncertain = intent is not None and intent["state"] in ("executing", "unknown")
        if (uncertain or run["reconcile_required"]) and not self.no_reconcile:
            if self.reconcile(run, token, key, intent) == "done":
                return
            if run["state"] == "awaiting_approval":  # restored run, nothing happened externally
                with self.pool.connection() as conn, conn.cursor() as cur:
                    self.lock_lease(cur, run["id"], token)
                    cur.execute("UPDATE wf.workflow_runs SET reconcile_required=false, due_at=approval_deadline,"
                                " version=version+1 WHERE id=%s", (run["id"],))
                    self.release(cur, run["id"], token)
                return
        elif uncertain or run["reconcile_required"]:
            self.log(f"run={run['id']} NO_RECONCILE: ignoring intent state "
                     f"{intent['state'] if intent else None} / reconcile_required={run['reconcile_required']}")
        self.execute(run, token, key)

    def reconcile(self, run: dict, token: int, key: str, intent: dict | None) -> str:
        status, body = http("GET", f"{self.ticket_url}/tickets?" + urllib.parse.urlencode({"idempotency_key": key}))
        with self.pool.connection() as conn, conn.cursor() as cur:
            self.lock_lease(cur, run["id"], token)
            if status == 200 and body["tickets"]:
                tid = body["tickets"][0]["id"]
                if intent:
                    cur.execute("UPDATE wf.execution_intents SET state='reconciled', fencing_token=%s,"
                                " updated_at=clock_timestamp() WHERE operation_key=%s", (token, key))
                else:
                    cur.execute("INSERT INTO wf.execution_intents (operation_key, run_id, tenant_id, fencing_token,"
                                " state, attempt) VALUES (%s,%s,%s,%s,'reconciled',0)",
                                (key, run["id"], run["tenant_id"], token))
                cur.execute("INSERT INTO wf.execution_results (operation_key, run_id, outcome, ticket_id, fencing_token,"
                            " handler_version) VALUES (%s,%s,'adopted',%s,%s,%s)",
                            (key, run["id"], tid, token, run["handler_version"]))
                self.finish(cur, run, token, "completed", f"adopted {tid} found by lookup", "reconciled_adopted")
                return "done"
            if status == 501:
                self.park_for_operator(cur, run, token, "outcome of an earlier attempt is unknown and the external "
                                       "system cannot be searched by idempotency key")
                return "done"
            if status == 200:
                self.event(cur, run["id"], "reconciled_absent", "lookup found no ticket for the operation key", token)
                return "absent"
            cur.execute("UPDATE wf.workflow_runs SET due_at = now() + interval '1 second' WHERE id=%s", (run["id"],))
            self.release(cur, run["id"], token)
            self.event(cur, run["id"], "lookup_failed", f"HTTP {status} {body}", token)
            return "done"

    def gate(self, run: dict, token: int, key: str) -> bool:
        """One transaction: lease + token still ours, run still executable, approval still valid,
        approver still permitted, then record the intent. Returns True if the effect may proceed."""
        with self.pool.connection() as conn, conn.cursor() as cur:
            self.lock_lease(cur, run["id"], token)
            cur.execute("SELECT *, now() AS db_now FROM wf.workflow_runs WHERE id=%s FOR UPDATE", (run["id"],))
            r = cur.fetchone()
            if r["state"] not in ("ready", "retry_wait", "executing"):
                self.release(cur, run["id"], token)
                self.log(f"run={run['id']} gate: state is {r['state']}, nothing to do")
                return False
            if r["cancel_requested"]:
                self.finish(cur, r, token, "cancelled", "cancel requested before the effect")
                return False
            cur.execute("SELECT * FROM wf.approvals WHERE run_id=%s ORDER BY id DESC LIMIT 1 FOR UPDATE", (run["id"],))
            a = cur.fetchone()
            cur.execute("SELECT 1 FROM wf.grants WHERE tenant_id=%s AND principal=%s AND permission=%s"
                        " AND revoked_at IS NULL", (r["tenant_id"], a["approver"] if a else "", "approve_remediation"))
            permitted = cur.fetchone() is not None
            cur.execute("SELECT * FROM wf.execution_intents WHERE operation_key=%s FOR UPDATE", (key,))
            intent = cur.fetchone()
            deny = None
            if a is None:
                deny = ("denied", "no approval on record")
            elif a["revoked_at"] is not None:
                deny = ("denied", f"approval {a['id']} revoked at {a['revoked_at'].isoformat()}")
            elif a["proposal_digest"] != r["proposal_digest"]:
                deny = ("approval_mismatch",
                        f"approved digest {a['proposal_digest'][:16]} != proposal digest {r['proposal_digest'][:16]}")
            elif a["expires_at"] <= r["db_now"]:
                deny = ("approval_expired", f"approval {a['id']} expired at {a['expires_at'].isoformat()}")
            elif not permitted:
                deny = ("denied", f"approver {a['approver']} no longer holds approve_remediation")
            elif intent is None and a["uses"] >= a["max_uses"]:
                deny = ("denied", f"approval {a['id']} already used {a['uses']}/{a['max_uses']}")
            elif r["attempts"] >= r["max_attempts"]:
                deny = ("dead_lettered", f"{r['attempts']} attempts used of max {r['max_attempts']}")
            if deny:
                self.finish(cur, r, token, deny[0], deny[1])
                return False
            if intent is None:
                cur.execute("UPDATE wf.approvals SET uses = uses + 1 WHERE id=%s", (a["id"],))
                cur.execute("INSERT INTO wf.execution_intents (operation_key, run_id, tenant_id, fencing_token, state,"
                            " attempt) VALUES (%s,%s,%s,%s,'prepared',1)", (key, r["id"], r["tenant_id"], token))
            else:
                cur.execute("UPDATE wf.execution_intents SET state='prepared', fencing_token=%s, attempt=attempt+1,"
                            " updated_at=clock_timestamp() WHERE operation_key=%s", (token, key))
            cur.execute("UPDATE wf.workflow_runs SET state='executing', step='effect', attempts=attempts+1,"
                        " reconcile_required=false, version=version+1, updated_at=clock_timestamp() WHERE id=%s",
                        (r["id"],))
            self.event(cur, r["id"], "gate_passed", f"attempt {r['attempts'] + 1} approval {a['id']}", token)
            return True

    def execute(self, run: dict, token: int, key: str) -> None:
        self.hook("WFSPIKE_PAUSE_BEFORE_GATE_FILE", run["id"], token)
        if not self.gate(run, token, key):
            return
        self.hook("WFSPIKE_PAUSE_AFTER_PREPARE_FILE", run["id"], token)
        with self.pool.connection() as conn, conn.cursor() as cur:
            self.lock_lease(cur, run["id"], token)
            cur.execute("UPDATE wf.execution_intents SET state='executing', updated_at=clock_timestamp()"
                        " WHERE operation_key=%s AND fencing_token=%s AND state='prepared'", (key, token))
            if cur.rowcount != 1:
                raise Fenced(f"run={run['id']} intent no longer prepared under token {token}")
        self.hook("WFSPIKE_PAUSE_BEFORE_EFFECT_FILE", run["id"], token)

        handler = HANDLERS[run["handler_version"]]
        status, body = http("POST", f"{self.ticket_url}/tickets", handler.request(run, key, token))
        self.log(f"run={run['id']} token={token} POST /tickets -> {status} {body}")
        if status in (200, 201):
            self.hook("WFSPIKE_HANG_AFTER_EFFECT_FILE", run["id"], token)
            self.record_success(run, token, key, body["id"], "created" if status == 201 else "deduplicated_by_external")
        elif status == 409:
            with self.pool.connection() as conn, conn.cursor() as cur:
                self.event(cur, run["id"], "external_rejected_stale_token", json.dumps(body), token)
        else:
            self.record_failure(run, token, key, definite=(status == 503), err=f"HTTP {status} {body}")

    def record_success(self, run: dict, token: int, key: str, tid: str, outcome: str) -> None:
        try:
            with self.pool.connection() as conn, conn.cursor() as cur:
                self.lock_lease(cur, run["id"], token)
                cur.execute("UPDATE wf.execution_intents SET state='succeeded', updated_at=clock_timestamp()"
                            " WHERE operation_key=%s", (key,))
                cur.execute("INSERT INTO wf.execution_results (operation_key, run_id, outcome, ticket_id, fencing_token,"
                            " handler_version) VALUES (%s,%s,%s,%s,%s,%s)",
                            (key, run["id"], outcome, tid, token, run["handler_version"]))
                self.finish(cur, run, token, "completed", f"{outcome} {tid} (handler v{run['handler_version']})")
        except Fenced as e:
            with self.pool.connection() as conn, conn.cursor() as cur:
                cur.execute("UPDATE wf.execution_intents SET state='unknown', updated_at=clock_timestamp()"
                            " WHERE operation_key=%s AND fencing_token=%s AND state='executing'", (key, token))
                self.event(cur, run["id"], "stale_effect_result",
                           f"call under stale token {token} returned ticket {tid}; NOT recorded as result ({e})", token)
            self.log(f"run={run['id']} STALE RESULT: call under token {token} returned {tid}; not recorded: {e}")

    def record_failure(self, run: dict, token: int, key: str, definite: bool, err: str) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            self.lock_lease(cur, run["id"], token)
            cur.execute("SELECT * FROM wf.workflow_runs WHERE id=%s FOR UPDATE", (run["id"],))
            r = cur.fetchone()
            cur.execute("UPDATE wf.execution_intents SET state=%s, updated_at=clock_timestamp() WHERE operation_key=%s",
                        ("failed" if definite else "unknown", key))
            if r["attempts"] >= r["max_attempts"]:
                if definite:
                    self.finish(cur, r, token, "dead_lettered", f"{r['attempts']} attempts exhausted; last: {err}")
                else:
                    self.park_for_operator(cur, r, token, f"attempts exhausted with unknown outcome; last: {err}")
                return
            delay = min(self.backoff_cap, self.backoff_base * 2 ** (r["attempts"] - 1))
            cur.execute("UPDATE wf.workflow_runs SET state='retry_wait', step='backoff',"
                        " due_at = now() + make_interval(secs => %s), version=version+1, updated_at=clock_timestamp()"
                        " WHERE id=%s", (delay, r["id"]))
            self.release(cur, r["id"], token)
            self.event(cur, r["id"], "retry_scheduled",
                       f"attempt {r['attempts']} {'failed' if definite else 'outcome unknown'} ({err}); "
                       f"retry in {delay}s", token)
            self.log(f"run={r['id']} attempt {r['attempts']} failed; retry in {delay}s")

    # ---- main loop -----------------------------------------------------------------------------
    def run_forever(self) -> None:
        self.pool.wait(30)
        self.log(f"WORKER READY versions={self.versions} lease_ttl={self.lease_ttl}s "
                 f"no_reconcile={self.no_reconcile} pid={os.getpid()}")
        while True:
            claimed = None
            try:
                claimed = self.claim()
                if claimed is None:
                    time.sleep(self.poll)
                    continue
                run, token = claimed
                self.current = (run["id"], token)
                self.log(f"claimed run={run['id']} tenant={run['tenant_id']} state={run['state']} token={token}")
                self.process(run, token)
            except Fenced as e:
                self.log(f"FENCED, refusing to act: {e}")
                if claimed:
                    try:
                        with self.pool.connection() as conn, conn.cursor() as cur:
                            self.event(cur, claimed[0]["id"], "fenced_refused", str(e), claimed[1])
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as e:  # noqa: BLE001  (DB down etc.): log, back off, keep going
                self.log(f"error: {type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}")
                time.sleep(0.5)
            finally:
                self.current = None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--ticket-url", required=True)
    ap.add_argument("--handler-versions", default="1")
    ap.add_argument("--lease-ttl", type=float, default=3.0)
    ap.add_argument("--poll", type=float, default=0.2)
    ap.add_argument("--backoff-base", type=float, default=0.5)
    ap.add_argument("--backoff-cap", type=float, default=5.0)
    a = ap.parse_args()
    Worker(os.environ["WFSPIKE_DSN"], a.name, a.ticket_url, [int(v) for v in a.handler_versions.split(",")],
           a.lease_ttl, a.poll, a.backoff_base, a.backoff_cap).run_forever()


if __name__ == "__main__":
    main()
