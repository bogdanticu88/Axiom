"""SLA timers v2 (provisional targets; ADR 0011).

Two clocks per case cycle (a cycle starts at creation, and again at each reopening):

* **Triage**: starts at the cycle start; ends when the case is first prioritised (policy applied or override) in that
  cycle. It is a deadline to *decide priority*, not to remediate. Met if prioritised by the due time, otherwise missed.
* **Remediation**: starts at the first prioritisation in the cycle; due = start + target for the current priority +
  paused time. A priority change *revises* the timer: the old row ends as ``revised`` and a new row keeps the **same
  start and accumulated pause** with the new target, so elapsed time is never reset. If the new due time has already
  passed, the revised timer is breached at that due time.
* **Pause**: when the SLA policy says ``pause_on_deferral``, the clock stops from a ``case.deferred`` event until the
  next case event (the deferral is replaced by any further decision). Pauses are derived from event timestamps, so the
  result does not depend on when the sweep runs.
* **Breach** time is the due time itself (deterministic), recorded once with one outbox event.
* **End**: on closure, ``verified_remediated`` ends the remediation timer as ``met`` (closed by the due time) or
  ``missed``; ``accepted_risk`` ends it as ``risk_accepted`` (never ``met``: accepted risk is not remediation);
  dismissed, duplicate and retired-asset closures end it as ``closed_without_fix``. An open triage timer at closure
  ends the same way.

Targets come from the published ``sla`` policy or the built-in provisional default, recorded on every timer.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...db import TenantContext
from ..policies.service import current

KIND = "cases.sla_sweep"
PRIORITY_EVENTS = ("case.prioritised", "case.priority_overridden")


def _cycle(events: list[dict]) -> tuple[int, list[dict]]:
    reopen = [i for i, e in enumerate(events) if e["event_type"] == "case.reopened"]
    start = reopen[-1] if reopen else 0
    return len(reopen) + 1, events[start:]


def _paused(events: list[dict], since, until, enabled: bool) -> tuple[float, object]:
    """Seconds paused between ``since`` and ``until`` and the start of a pause still open at ``until``."""
    if not enabled:
        return 0.0, None
    total, open_since = 0.0, None
    for i, e in enumerate(events):
        if e["event_type"] != "case.deferred":
            continue
        start = max(e["created_at"], since)
        nxt = events[i + 1]["created_at"] if i + 1 < len(events) else None
        end = min(nxt, until) if nxt else until
        if end > start:
            total += (end - start).total_seconds()
        if nxt is None or nxt > until:
            open_since = start if start <= until else None
    return total, open_since


def _end_status(reason: str | None, due, closed_at, breached: bool) -> str:
    if reason == "verified_remediated":
        return "met" if not breached and closed_at <= due else "missed"
    if reason == "accepted_risk":
        return "risk_accepted"
    return "closed_without_fix"


def sla_sweep(conn: psycopg.Connection, ctx: TenantContext, *, now=None) -> dict:
    """``now`` may be supplied by tests to evaluate the clocks at a later instant; workers use the database clock."""
    out = {"started": 0, "revised": 0, "breached": 0, "ended": 0, "paused": 0, "resumed": 0}
    definition, policy_id, provisional = current(conn, "sla")
    snapshot = {**definition, "provisional": provisional, "policy_version_id": str(policy_id) if policy_id else None}
    if now is None:
        now = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    cases = conn.execute("SELECT * FROM axiom.finding_cases FOR UPDATE SKIP LOCKED").fetchall()
    for case in cases:
        events = list(conn.execute(
            "SELECT event_type, created_at, payload FROM axiom.case_events WHERE case_id = %s ORDER BY sequence",
            (case["id"],)))
        if not events:
            continue
        cycle, evs = _cycle(events)
        cycle_start = evs[0]["created_at"]
        closed = evs[-1]["event_type"].startswith("case.closed.")
        closure_reason = evs[-1]["event_type"].removeprefix("case.closed.") if closed else None
        closed_at = evs[-1]["created_at"] if closed else None
        prio_events = [e for e in evs if e["event_type"] in PRIORITY_EVENTS]
        timers = {r["kind"]: r for r in conn.execute(
            "SELECT * FROM axiom.sla_timers WHERE case_id = %s AND cycle = %s AND status IN ('running','paused','breached')",
            (case["id"], cycle))}
        done = {r["kind"] for r in conn.execute(
            "SELECT DISTINCT kind FROM axiom.sla_timers WHERE case_id = %s AND cycle = %s", (case["id"], cycle))}
        if closed and not timers:
            continue      # everything for this cycle has already ended

        # ---- triage
        if "triage" not in done:
            due = cycle_start + timedelta(days=definition["triage_days"])
            timers["triage"] = _insert(conn, ctx, case["id"], "triage", cycle, case["priority"], policy_id, snapshot,
                                       cycle_start, due)
            out["started"] += 1
        t = timers.get("triage")
        if t is not None:
            end_at = prio_events[0]["created_at"] if prio_events else closed_at
            if end_at is not None:
                breached = t["breached_at"] is not None or end_at > t["due_at"]
                status = ("missed" if breached else "met") if prio_events else _end_status(closure_reason, t["due_at"],
                                                                                            end_at, True)
                _end(conn, t, status, end_at, "prioritised" if prio_events else f"closed: {closure_reason}",
                     breach_at=t["due_at"] if breached and t["breached_at"] is None else None)
                out["ended"] += 1
            elif t["due_at"] <= now and t["breached_at"] is None:
                _breach(conn, ctx, t, out)

        # ---- remediation
        if not prio_events:
            continue
        start = prio_events[0]["created_at"]
        target = definition["remediation_days"][case["priority"]] if case["priority"] in \
            definition["remediation_days"] else None
        horizon = closed_at or now
        paused, open_pause = _paused(evs, start, horizon, definition.get("pause_on_deferral", False))
        if target is None:
            continue
        due = start + timedelta(days=target, seconds=paused)
        r = timers.get("remediation")
        if r is not None and r["priority"] != case["priority"]:
            # revise, never reset: the new timer keeps the original start and the accumulated pause
            _end(conn, r, "revised", now, f"priority {r['priority']} -> {case['priority']}")
            out["revised"] += 1
            r = None
        if r is None:
            final = conn.execute(
                """SELECT 1 FROM axiom.sla_timers WHERE case_id = %s AND cycle = %s AND kind = 'remediation'
                     AND status NOT IN ('revised', 'running', 'paused', 'breached')""", (case["id"], cycle)).fetchone()
            if final is None:
                r = _insert(conn, ctx, case["id"], "remediation", cycle, case["priority"], policy_id, snapshot, start,
                            due)
                out["started"] += 1
        if r is None:
            continue
        if closed:
            breached = r["breached_at"] is not None or closed_at > due
            _end(conn, r, _end_status(closure_reason, due, closed_at, breached), closed_at, f"closed: {closure_reason}",
                 breach_at=due if breached and r["breached_at"] is None and closure_reason == "verified_remediated"
                 else None, paused=paused, due=due)
            out["ended"] += 1
            continue
        status = r["status"]
        if open_pause is not None:
            status = "paused" if r["breached_at"] is None else "breached"
            out["paused"] += r["status"] != "paused"
        elif r["status"] == "paused":
            status = "running"
            out["resumed"] += 1
        conn.execute("""UPDATE axiom.sla_timers SET paused_seconds = GREATEST(paused_seconds, %s), due_at = %s, status = %s,
                               paused_since = %s, record_version = record_version + 1 WHERE id = %s""",
                     (int(paused), due, status, open_pause if status == "paused" else None, r["id"]))
        if open_pause is None and r["breached_at"] is None and due <= now:
            r = conn.execute("SELECT * FROM axiom.sla_timers WHERE id = %s", (r["id"],)).fetchone()
            _breach(conn, ctx, r, out)
    return out


def _insert(conn, ctx, case_id, kind, cycle, priority, policy_id, snapshot, start, due) -> dict:
    return conn.execute(
        """INSERT INTO axiom.sla_timers(tenant_id, id, case_id, kind, cycle, priority, policy_version_id, policy_snapshot,
               started_at, due_at, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'running') RETURNING *""",
        (ctx.tenant_id, uuid.uuid4(), case_id, kind, cycle, priority, policy_id, Jsonb(snapshot), start, due)).fetchone()


def _end(conn, timer, status, ended_at, reason, *, breach_at=None, paused=None, due=None) -> None:
    conn.execute(
        """UPDATE axiom.sla_timers SET status = %s, ended_at = %s, end_reason = %s, paused_since = NULL,
                  breached_at = COALESCE(breached_at, %s), paused_seconds = GREATEST(paused_seconds, %s),
                  due_at = COALESCE(%s, due_at), record_version = record_version + 1 WHERE id = %s""",
        (status, ended_at, reason, breach_at, int(paused or 0), due, timer["id"]))


def _breach(conn, ctx, timer, out) -> None:
    conn.execute("""UPDATE axiom.sla_timers SET status = 'breached', breached_at = due_at, paused_since = NULL,
                           record_version = record_version + 1 WHERE id = %s""", (timer["id"],))
    audit.record(conn, ctx, action=f"sla.{timer['kind']}_breached", resource_type="finding_case",
                 resource_id=timer["case_id"], detail={"due_at": timer["due_at"].isoformat()})
    outbox.enqueue(conn, ctx, topic=f"sla.{timer['kind']}_breached", aggregate_type="finding_case",
                   aggregate_id=timer["case_id"], payload={"due_at": timer["due_at"].isoformat()})
    out["breached"] += 1


class SlaSweepHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc):
        from ...jobs import Done
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            return Done(sla_sweep(conn, jc.ctx))
