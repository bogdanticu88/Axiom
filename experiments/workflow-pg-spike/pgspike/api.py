"""Platform-side operations (what the API / operator CLI would do). Each function is one transaction.

In the spike the tests call these with an owner connection. In the platform they would run as the
API role under RLS, in the same transaction as the audit/outbox rows.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA_SQL = (Path(__file__).parent / "schema.sql").read_text()
TERMINAL = ("completed", "approval_expired", "approval_mismatch", "denied", "cancelled", "dead_lettered", "abandoned")
APPROVE_PERMISSION = "approve_remediation"


class Rejected(Exception):
    """The platform refused the request (late approval, wrong state, missing permission...)."""


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def operation_key(run_id, digest: str) -> str:
    return hashlib.sha256(f"{run_id}:{digest}".encode()).hexdigest()


def install_schema(conn: psycopg.Connection, worker_role: str) -> None:
    with conn.transaction():
        conn.execute(SCHEMA_SQL)
        grant_worker(conn, worker_role)


def grant_worker(conn: psycopg.Connection, role: str) -> None:
    """Workers get DML on the wf schema only: no DDL, no DELETE, no superuser."""
    conn.execute(f'GRANT USAGE ON SCHEMA wf TO "{role}"')
    conn.execute(f'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA wf TO "{role}"')
    conn.execute(f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA wf TO "{role}"')


def _event(cur, run_id, event: str, detail: str = "", who: str = "api") -> None:
    cur.execute("INSERT INTO wf.run_events (run_id, event, detail, worker) VALUES (%s,%s,%s,%s)",
                (run_id, event, detail, who))


def grant(conn, tenant: str, principal: str) -> None:
    with conn.transaction():
        conn.execute(
            "INSERT INTO wf.grants VALUES (%s,%s,%s,NULL) ON CONFLICT (tenant_id, principal, permission)"
            " DO UPDATE SET revoked_at = NULL", (tenant, principal, APPROVE_PERMISSION))


def revoke_grant(conn, tenant: str, principal: str) -> None:
    with conn.transaction():
        conn.execute("UPDATE wf.grants SET revoked_at = clock_timestamp() WHERE tenant_id=%s AND principal=%s",
                     (tenant, principal))


def set_tenant_limit(conn, tenant: str, n: int) -> None:
    with conn.transaction():
        conn.execute("INSERT INTO wf.tenant_limits VALUES (%s,%s) ON CONFLICT (tenant_id) DO UPDATE SET"
                     " max_concurrent = EXCLUDED.max_concurrent", (tenant, n))


def create_run(conn, tenant: str, proposal: dict, *, approval_window_s: float = 3600, max_attempts: int = 5,
               handler_version: int = 1, kind: str = "open_remediation_ticket") -> uuid.UUID:
    run_id = uuid.uuid4()
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("INSERT INTO wf.tenant_limits (tenant_id) VALUES (%s) ON CONFLICT DO NOTHING", (tenant,))
        cur.execute(
            """INSERT INTO wf.workflow_runs (tenant_id, id, kind, state, step, proposal, proposal_digest,
                   approval_deadline, due_at, max_attempts, handler_version)
               VALUES (%s,%s,%s,'awaiting_approval','await_approval',%s,%s,
                   now() + make_interval(secs => %s), now() + make_interval(secs => %s), %s, %s)""",
            (tenant, run_id, kind, Jsonb(proposal), digest_of(proposal), approval_window_s, approval_window_s,
             max_attempts, handler_version))
        cur.execute("INSERT INTO wf.job_leases (run_id) VALUES (%s)", (run_id,))
        _event(cur, run_id, "created", f"handler_version={handler_version} window={approval_window_s}s")
    return run_id


def approve(conn, run_id, approver: str, digest: str, *, valid_for_s: float = 600, max_uses: int = 1) -> int:
    """Record an approval. The digest is stored as given; the worker's gate compares it with the
    run's digest (so a substituted-argument approval is refused at use time, as in the Temporal spike)."""
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT tenant_id, state FROM wf.workflow_runs WHERE id=%s FOR UPDATE", (run_id,))
        run = cur.fetchone()
        if run is None:
            raise Rejected(f"run {run_id} not found")
        if run["state"] != "awaiting_approval":
            raise Rejected(f"run {run_id} is {run['state']}, not awaiting_approval")
        cur.execute("SELECT 1 FROM wf.grants WHERE tenant_id=%s AND principal=%s AND permission=%s"
                    " AND revoked_at IS NULL", (run["tenant_id"], approver, APPROVE_PERMISSION))
        if cur.fetchone() is None:
            raise Rejected(f"{approver} may not approve for tenant {run['tenant_id']}")
        cur.execute(
            """INSERT INTO wf.approvals (run_id, tenant_id, approver, proposal_digest, expires_at, max_uses)
               VALUES (%s,%s,%s,%s, now() + make_interval(secs => %s), %s) RETURNING id""",
            (run_id, run["tenant_id"], approver, digest, valid_for_s, max_uses))
        aid = cur.fetchone()["id"]
        cur.execute("UPDATE wf.workflow_runs SET state='ready', step='execute', due_at=now(), version=version+1,"
                    " updated_at=clock_timestamp() WHERE id=%s", (run_id,))
        _event(cur, run_id, "approved", f"approval {aid} by {approver} digest={digest[:16]}", approver)
    return aid


def revoke_approval(conn, run_id) -> None:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("UPDATE wf.approvals SET revoked_at = clock_timestamp() WHERE run_id=%s AND revoked_at IS NULL",
                    (run_id,))
        _event(cur, run_id, "approval_revoked", f"{cur.rowcount} approval(s)")


def request_cancel(conn, run_id) -> None:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("UPDATE wf.workflow_runs SET cancel_requested = true, version=version+1,"
                    " updated_at=clock_timestamp() WHERE id=%s", (run_id,))
        _event(cur, run_id, "cancel_requested")


def operator_resolve(conn, run_id, decision: str, ticket_id: str | None, operator: str, note: str = "") -> None:
    if decision not in ("adopt", "abandon"):
        raise ValueError(decision)
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM wf.workflow_runs WHERE id=%s FOR UPDATE", (run_id,))
        run = cur.fetchone()
        if run["state"] != "needs_operator_reconciliation":
            raise Rejected(f"run is {run['state']}")
        key = operation_key(run_id, run["proposal_digest"])
        if decision == "adopt":
            cur.execute("UPDATE wf.execution_intents SET state='reconciled', updated_at=clock_timestamp()"
                        " WHERE operation_key=%s", (key,))
            cur.execute("INSERT INTO wf.execution_results (operation_key, run_id, outcome, ticket_id, handler_version)"
                        " VALUES (%s,%s,'operator_adopted',%s,%s)", (key, run_id, ticket_id, run["handler_version"]))
            state, detail = "completed", f"operator {operator} adopted {ticket_id}"
        else:
            state, detail = "abandoned", f"operator {operator} abandoned: {note}"
        cur.execute("UPDATE wf.workflow_runs SET state=%s, step='done', due_at=NULL, detail=%s, version=version+1,"
                    " updated_at=clock_timestamp(), finished_at=clock_timestamp() WHERE id=%s", (state, detail, run_id))
        _event(cur, run_id, f"operator_{decision}", detail, operator)


def mark_restored(conn) -> int:
    """Post-restore runbook step: every non-terminal run may have progressed (in the real world)
    after the backup was taken, so it must reconcile against the external system before any effect."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "UPDATE wf.workflow_runs SET reconcile_required = true, due_at = now(), version=version+1,"
            " updated_at=clock_timestamp() WHERE state <> ALL(%s) AND state <> 'needs_operator_reconciliation'",
            (list(TERMINAL),))
        n = cur.rowcount
        # Leases copied from the backup refer to workers of the old world: expire them.
        cur.execute("UPDATE wf.job_leases SET lease_owner=NULL, lease_expires_at=NULL")
        return n


def migrate_handler(conn, run_id, from_v: int, to_v: int) -> None:
    """Explicit migration of one run to a newer handler. Only allowed before any effect was attempted
    and while no worker holds the run."""
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """SELECT r.state, r.handler_version, l.lease_expires_at > now() AS leased,
                      (SELECT count(*) FROM wf.execution_intents i WHERE i.run_id = r.id) AS intents
               FROM wf.workflow_runs r JOIN wf.job_leases l ON l.run_id = r.id WHERE r.id=%s FOR UPDATE OF r, l""",
            (run_id,))
        r = cur.fetchone()
        if r["handler_version"] != from_v or r["state"] not in ("awaiting_approval", "ready") or r["leased"] \
                or r["intents"]:
            raise Rejected(f"cannot migrate: {r}")
        cur.execute("UPDATE wf.workflow_runs SET handler_version=%s, version=version+1, updated_at=clock_timestamp()"
                    " WHERE id=%s", (to_v, run_id))
        _event(cur, run_id, "handler_migrated", f"v{from_v} -> v{to_v}")


def drain_status(conn) -> dict[int, int]:
    """Non-terminal runs per handler version: a version's code may be removed when this reaches 0."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT handler_version AS v, count(*) AS n FROM wf.workflow_runs WHERE state <> ALL(%s)"
                    " GROUP BY 1 ORDER BY 1", (list(TERMINAL),))
        return {r["v"]: r["n"] for r in cur.fetchall()}
