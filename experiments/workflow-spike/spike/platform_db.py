"""SQLite stand-in for the platform database (proposals, execution intents, results, audit events).

All tables are append-only from the workflow's point of view. Intent is written BEFORE the
external effect, the result AFTER, so a crash between the two leaves an unresolved intent.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    workflow_id     TEXT PRIMARY KEY,
    canonical_json  TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_intents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key   TEXT NOT NULL,
    workflow_id     TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    attempt         INTEGER NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key   TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    ticket_id       TEXT,
    attempt         INTEGER NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id     TEXT NOT NULL,
    event           TEXT NOT NULL,
    detail          TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)  # autocommit
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def save_proposal(path: str, workflow_id: str, canonical_json: str, digest: str) -> None:
    with closing(connect(path)) as c:
        c.execute(
            "INSERT OR IGNORE INTO proposals VALUES (?,?,?,?)",
            (workflow_id, canonical_json, digest, _now()),
        )


def unresolved_intents(path: str, operation_key: str) -> int:
    """Intents for this key that have no recorded result (i.e. outcome unknown)."""
    with closing(connect(path)) as c:
        n_int = c.execute(
            "SELECT COUNT(*) FROM execution_intents WHERE operation_key=?", (operation_key,)
        ).fetchone()[0]
        n_res = c.execute(
            "SELECT COUNT(*) FROM execution_results WHERE operation_key=?", (operation_key,)
        ).fetchone()[0]
        return n_int if n_res == 0 else 0


def record_intent(path: str, operation_key: str, workflow_id: str, digest: str, attempt: int) -> None:
    with closing(connect(path)) as c:
        c.execute(
            "INSERT INTO execution_intents (operation_key, workflow_id, payload_digest, attempt, recorded_at)"
            " VALUES (?,?,?,?,?)",
            (operation_key, workflow_id, digest, attempt, _now()),
        )


def record_result(path: str, operation_key: str, outcome: str, ticket_id: str | None, attempt: int) -> None:
    with closing(connect(path)) as c:
        c.execute(
            "INSERT INTO execution_results (operation_key, outcome, ticket_id, attempt, recorded_at)"
            " VALUES (?,?,?,?,?)",
            (operation_key, outcome, ticket_id, attempt, _now()),
        )


def record_event(path: str, workflow_id: str, event: str, detail: str) -> None:
    with closing(connect(path)) as c:
        c.execute(
            "INSERT INTO workflow_events (workflow_id, event, detail, recorded_at) VALUES (?,?,?,?)",
            (workflow_id, event, detail, _now()),
        )


def dump(path: str, table: str) -> list[dict]:
    assert table in {"proposals", "execution_intents", "execution_results", "workflow_events"}
    with closing(connect(path)) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY rowid")]
