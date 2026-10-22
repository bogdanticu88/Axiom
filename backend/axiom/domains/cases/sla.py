"""SLA timers for open cases (Implementation Plan S 8, Phase D).

Thresholds are **defaults pending the business decision** on SLA targets (D-SLA-1 in DECISIONS.md) and are stored
with each timer. A timer starts when the case is created (or reopened), runs against the case's priority, is
superseded with the same start time when the priority changes, is marked breached once when overdue (one outbox
event), and ends when the case closes: ``met`` if closed before breach, ``missed`` otherwise, with the closure reason.
Deferral does not pause the timer.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import timedelta

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...db import TenantContext

KIND = "cases.sla_sweep"


@dataclass(frozen=True)
class SlaPolicy:
    days: dict = field(default_factory=lambda: {"urgent": 7, "high": 30, "medium": 90, "low": 180, "pending": 14})


DEFAULT_SLA = SlaPolicy()


def sla_sweep(conn: psycopg.Connection, ctx: TenantContext, policy: SlaPolicy = DEFAULT_SLA) -> dict:
    out = {"started": 0, "superseded": 0, "breached": 0, "ended": 0}
    now = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]

    def start(case, started_at):
        due = started_at + timedelta(days=policy.days[case["priority"]])
        status = "breached" if due <= now else "running"
        conn.execute(
            """INSERT INTO axiom.case_slas(tenant_id, id, case_id, priority, policy, started_at, due_at, status,
                   breached_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (ctx.tenant_id, uuid.uuid4(), case["id"], case["priority"], Jsonb(asdict(policy)), started_at, due,
             status, now if status == "breached" else None))
        if status == "breached":
            _breach_event(conn, ctx, case["id"], due)
            out["breached"] += 1
        out["started"] += 1

    rows = conn.execute(
        """SELECT c.id, c.priority, c.workflow, c.created_at, s.id AS sla_id, s.priority AS sla_priority,
                  s.status AS sla_status, s.started_at, s.due_at,
                  (SELECT max(e.created_at) FROM axiom.case_events e WHERE e.case_id = c.id
                     AND e.event_type = 'case.reopened') AS reopened_at,
                  (SELECT cr.reason FROM axiom.closure_records cr WHERE cr.case_id = c.id
                     AND cr.case_event_sequence = c.record_version) AS closure_reason
             FROM axiom.finding_cases c
             LEFT JOIN axiom.case_slas s ON s.case_id = c.id AND s.status IN ('running', 'breached')
            FOR UPDATE OF c SKIP LOCKED""").fetchall()
    for r in rows:
        if r["workflow"] == "closed":
            if r["sla_id"] is not None:
                final = "met" if r["sla_status"] == "running" else "missed"
                conn.execute("""UPDATE axiom.case_slas SET status = %s, ended_at = clock_timestamp(), end_reason = %s,
                                       record_version = record_version + 1 WHERE id = %s""",
                             (final, f"case closed: {r['closure_reason']}", r["sla_id"]))
                out["ended"] += 1
            continue
        if r["sla_id"] is None:
            start(r, r["reopened_at"] or r["created_at"])
            continue
        if r["sla_priority"] != r["priority"]:
            ended = "superseded"
            conn.execute(
                """UPDATE axiom.case_slas SET status = %s, ended_at = clock_timestamp(), end_reason = %s,
                          breached_at = CASE WHEN status = 'breached' THEN breached_at ELSE NULL END,
                          record_version = record_version + 1 WHERE id = %s""",
                (ended, f"priority changed {r['sla_priority']} -> {r['priority']}", r["sla_id"]))
            out["superseded"] += 1
            start(r, r["started_at"])
            continue
        if r["sla_status"] == "running" and r["due_at"] <= now:
            conn.execute("""UPDATE axiom.case_slas SET status = 'breached', breached_at = clock_timestamp(),
                                   record_version = record_version + 1 WHERE id = %s""", (r["sla_id"],))
            _breach_event(conn, ctx, r["id"], r["due_at"])
            out["breached"] += 1
    return out


def _breach_event(conn, ctx, case_id, due) -> None:
    audit.record(conn, ctx, action="sla.breached", resource_type="finding_case", resource_id=case_id,
                 detail={"due_at": due.isoformat()})
    outbox.enqueue(conn, ctx, topic="sla.breached", aggregate_type="finding_case", aggregate_id=case_id,
                   payload={"due_at": due.isoformat()})


class SlaSweepHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc):
        from ...jobs import Done
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            return Done(sla_sweep(conn, jc.ctx))
