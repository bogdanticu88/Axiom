"""SQLite stand-in for the platform DB, used by the ids-only ("secure") workflow variant.

Unlike spike/platform_db.py, everything is keyed by (tenant_id, run_id), approvals are rows
written by "the API" (here: the test), and the workflow only ever receives identifiers and digests.

Tables
  action_proposals   canonical proposal JSON + digest, written by the API when the action is proposed
  approvals          approval decisions written by the API (RBAC/SoD happen there), revocable
  effect_claims      per operation key, the highest activity attempt that claimed the effect (fence)
  execution_intents  written BEFORE the external effect
  execution_results  written AFTER the external effect (or on adoption)
  workflow_events    audit trail of workflow decisions (codes only, no evidence text)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS action_proposals (
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    canonical_json  TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, run_id)
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    approver        TEXT NOT NULL,
    decided_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT
);
CREATE TABLE IF NOT EXISTS effect_claims (
    operation_key   TEXT PRIMARY KEY,
    fence           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_intents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key   TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    attempt         INTEGER NOT NULL,
    worker          TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key   TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    ticket_id       TEXT,
    attempt         INTEGER NOT NULL,
    worker          TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    event           TEXT NOT NULL,
    detail          TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
"""

TABLES = ("action_proposals", "approvals", "effect_claims", "execution_intents",
          "execution_results", "workflow_events")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def operation_key(tenant_id: str, run_id: str, digest: str) -> str:
    return hashlib.sha256(f"{tenant_id}:{run_id}:{digest}".encode()).hexdigest()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)  # autocommit; BEGIN IMMEDIATE when needed
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


# ---- written by "the API" (tests) ---------------------------------------------------------------
def put_proposal(path: str, tenant_id: str, run_id: str, proposal: dict) -> str:
    canon = canonical_json(proposal)
    digest = hashlib.sha256(canon.encode()).hexdigest()
    with closing(connect(path)) as c:
        c.execute("INSERT INTO action_proposals VALUES (?,?,?,?)", (tenant_id, run_id, canon, digest))
    return digest


def put_approval(path: str, approval_id: str, tenant_id: str, run_id: str, digest: str,
                 approver: str, expires_at: str) -> None:
    with closing(connect(path)) as c:
        c.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,NULL)",
                  (approval_id, tenant_id, run_id, digest, approver, now_iso(), expires_at))


def revoke_approval(path: str, approval_id: str) -> None:
    with closing(connect(path)) as c:
        c.execute("UPDATE approvals SET revoked_at=? WHERE approval_id=?", (now_iso(), approval_id))


# ---- read/written by activities -----------------------------------------------------------------
def get_proposal(path: str, tenant_id: str, run_id: str) -> tuple[str, str] | None:
    with closing(connect(path)) as c:
        row = c.execute("SELECT canonical_json, payload_digest FROM action_proposals WHERE tenant_id=? AND run_id=?",
                        (tenant_id, run_id)).fetchone()
    return (row[0], row[1]) if row else None


def approval_verdict(path: str, tenant_id: str, run_id: str, digest: str, approval_id: str) -> str:
    """Return a verdict code. The workflow never sees approver identity or evidence, only this code."""
    with closing(connect(path)) as c:
        row = c.execute("SELECT tenant_id, run_id, payload_digest, expires_at, revoked_at FROM approvals"
                        " WHERE approval_id=?", (approval_id,)).fetchone()
    if row is None:
        return "unknown_approval"
    a_tenant, a_run, a_digest, a_exp, a_revoked = row
    if (a_tenant, a_run) != (tenant_id, run_id):
        return "wrong_tenant_or_run"
    if a_digest != digest:
        return "digest_mismatch"
    if a_revoked is not None:
        return "revoked"
    if datetime.fromisoformat(a_exp) <= datetime.now(timezone.utc):
        return "expired"
    return "valid"


def claim_fence(path: str, op_key: str, attempt: int) -> int:
    """Raise the fence to `attempt` if higher; return the fence value after the update."""
    with closing(connect(path)) as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute("INSERT OR IGNORE INTO effect_claims VALUES (?, 0)", (op_key,))
        c.execute("UPDATE effect_claims SET fence=? WHERE operation_key=? AND fence < ?", (attempt, op_key, attempt))
        fence = c.execute("SELECT fence FROM effect_claims WHERE operation_key=?", (op_key,)).fetchone()[0]
        c.execute("COMMIT")
    return fence


def current_fence(path: str, op_key: str) -> int:
    with closing(connect(path)) as c:
        row = c.execute("SELECT fence FROM effect_claims WHERE operation_key=?", (op_key,)).fetchone()
    return row[0] if row else 0


def existing_result(path: str, op_key: str) -> tuple[str, str] | None:
    with closing(connect(path)) as c:
        row = c.execute("SELECT outcome, ticket_id FROM execution_results WHERE operation_key=? ORDER BY id LIMIT 1",
                        (op_key,)).fetchone()
    return (row[0], row[1]) if row else None


def record_intent(path: str, op_key: str, tenant_id: str, run_id: str, attempt: int, worker: str) -> None:
    with closing(connect(path)) as c:
        c.execute("INSERT INTO execution_intents (operation_key, tenant_id, run_id, attempt, worker, recorded_at)"
                  " VALUES (?,?,?,?,?,?)", (op_key, tenant_id, run_id, attempt, worker, now_iso()))


def record_result(path: str, op_key: str, outcome: str, ticket_id: str | None, attempt: int, worker: str) -> None:
    with closing(connect(path)) as c:
        c.execute("INSERT INTO execution_results (operation_key, outcome, ticket_id, attempt, worker, recorded_at)"
                  " VALUES (?,?,?,?,?,?)", (op_key, outcome, ticket_id, attempt, worker, now_iso()))


def record_event(path: str, tenant_id: str, run_id: str, event: str, detail: str) -> None:
    with closing(connect(path)) as c:
        c.execute("INSERT INTO workflow_events (tenant_id, run_id, event, detail, recorded_at) VALUES (?,?,?,?,?)",
                  (tenant_id, run_id, event, detail, now_iso()))


def dump(path: str, table: str) -> list[dict]:
    assert table in TABLES
    with closing(connect(path)) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY rowid")]
