"""SLA timers v2 (ADR 0011): triage vs remediation, pause on deferral, revise-not-reset, accepted risk, reopen, breach.

Targets are the built-in provisional defaults (triage 7 days; remediation low 180, medium 90, high 30, urgent 7) unless
a test publishes its own. Instants after "now" are evaluated by passing ``now=`` to the sweep (a clock injection the
worker never uses); event timestamps are the real database times.
"""
from __future__ import annotations

import time
from datetime import timedelta

import psycopg
import pytest

from axiom.domains.cases import priority as prio
from axiom.domains.cases.sla import sla_sweep

from .test_risk_two_step import now, review_case  # noqa: F401 - fixture

pytestmark = pytest.mark.db


def sweep(db, ctx, **kw):
    with db.tenant_tx(ctx) as conn:
        return sla_sweep(conn, ctx, **kw)


def timers(run, ctx, case_id):
    return run(ctx, lambda s: s.conn.execute(
        "SELECT * FROM axiom.sla_timers WHERE case_id = %s ORDER BY cycle, created_at", (case_id,)).fetchall())


def by(rows, kind):
    return [r for r in rows if r["kind"] == kind]


def test_triage_is_a_deadline_to_prioritise_not_to_remediate(db, run, ctx_for, review_case):
    system, analyst = ctx_for("system"), ctx_for("analyst")
    sweep(db, system)
    [t] = timers(run, analyst, review_case)
    assert (t["kind"], t["status"]) == ("triage", "running")
    assert t["due_at"] - t["started_at"] == timedelta(days=7)
    assert t["policy_snapshot"]["provisional"] is True and t["policy_version_id"] is None
    run(analyst, lambda s: prio.override(s.cases, review_case, 2, priority="high", rationale="exposed"))
    sweep(db, system)
    rows = timers(run, analyst, review_case)
    [tri], [rem] = by(rows, "triage"), by(rows, "remediation")
    assert (tri["status"], tri["end_reason"]) == ("met", "prioritised")
    prioritised_at = run(analyst, lambda s: s.cases.history(review_case))["events"][-1]["created_at"]
    assert rem["started_at"] == prioritised_at and rem["due_at"] - rem["started_at"] == timedelta(days=30)


def test_triage_missed_when_priority_comes_late_and_breach_is_recorded_once(db, run, ctx_for, review_case):
    system, analyst = ctx_for("system"), ctx_for("analyst")
    later = now(days=8)
    assert sweep(db, system, now=later)["breached"] == 1
    assert sweep(db, system, now=later)["breached"] == 0
    [t] = timers(run, analyst, review_case)
    assert t["status"] == "breached" and t["breached_at"] == t["due_at"]
    run(analyst, lambda s: prio.override(s.cases, review_case, 2, priority="medium", rationale="late"))
    sweep(db, system)
    tri = by(timers(run, analyst, review_case), "triage")[0]
    assert tri["status"] == "missed" and tri["breached_at"] == tri["due_at"]
    with pytest.raises(psycopg.errors.CheckViolation):     # an ended (breached) timer cannot be rewritten
        run(analyst, lambda s: s.conn.execute(
            "UPDATE axiom.sla_timers SET breached_at = NULL, record_version = record_version + 1 WHERE id = %s",
            (tri["id"],)))
    with db.tenant_tx(system) as conn:
        n = conn.execute("SELECT count(*) AS n FROM axiom.outbox WHERE topic = 'sla.triage_breached' AND aggregate_id = %s",
                         (review_case,)).fetchone()["n"]
    assert n == 1


def test_deferral_pauses_and_a_priority_change_revises_without_resetting(db, run, ctx_for, review_case):
    system, analyst = ctx_for("system"), ctx_for("analyst")
    run(analyst, lambda s: prio.override(s.cases, review_case, 2, priority="medium", rationale="initial"))
    sweep(db, system)
    first = by(timers(run, analyst, review_case), "remediation")[0]
    run(analyst, lambda s: s.cases.defer(review_case, 3, review_at=now(days=14), rationale="vendor patch due"))
    time.sleep(1.2)
    sweep(db, system)
    paused = by(timers(run, analyst, review_case), "remediation")[0]
    assert paused["status"] == "paused" and paused["paused_since"] is not None
    run(analyst, lambda s: prio.override(s.cases, review_case, 4, priority="urgent", rationale="exploit published"))
    out = sweep(db, system)
    assert out["revised"] == 1
    old, new = by(timers(run, analyst, review_case), "remediation")
    assert old["id"] == first["id"] and old["status"] == "revised" and "medium -> urgent" in old["end_reason"]
    assert new["started_at"] == first["started_at"]                       # elapsed time is never reset
    assert new["paused_seconds"] >= 1 and new["status"] == "running"
    # due = start + urgent target + paused time (paused_seconds is stored truncated to whole seconds)
    assert 0 <= (new["due_at"] - new["started_at"] - timedelta(days=7)).total_seconds() - new["paused_seconds"] < 1
    late = new["started_at"] + timedelta(days=8)
    sweep(db, system, now=late)
    breached = by(timers(run, analyst, review_case), "remediation")[-1]
    assert breached["status"] == "breached" and breached["breached_at"] == breached["due_at"]


def test_accepted_risk_is_never_counted_as_met_and_reopen_starts_a_new_cycle(db, run, ctx_for, review_case):
    system, analyst, owner = ctx_for("system"), ctx_for("analyst"), ctx_for("risk_owner")
    run(analyst, lambda s: prio.override(s.cases, review_case, 2, priority="low", rationale="internal only"))
    sweep(db, system)
    run(owner, lambda s: s.cases.accept_risk(review_case, 3, expires_at=now(days=30), rationale="compensating"))
    sweep(db, system)
    rem = by(timers(run, analyst, review_case), "remediation")[0]
    assert rem["status"] == "risk_accepted" and rem["ended_at"] is not None
    assert sweep(db, system) == {"started": 0, "revised": 0, "breached": 0, "ended": 0, "paused": 0, "resumed": 0}
    run(analyst, lambda s: s.cases.reopen(review_case, 4, reason="authorised_reassessment", rationale="exploit seen"))
    sweep(db, system)
    rows = timers(run, analyst, review_case)
    cycle2 = [r for r in rows if r["cycle"] == 2]
    assert [(r["kind"], r["status"]) for r in cycle2] == [("triage", "running")]
    reopened_at = run(analyst, lambda s: s.cases.history(review_case))["events"][-1]["created_at"]
    assert cycle2[0]["started_at"] == reopened_at
    assert [r["status"] for r in rows if r["cycle"] == 1] == ["met", "risk_accepted"]   # history kept


def test_published_sla_policy_is_recorded_on_the_timer(db, run, ctx_for, world, dbinfo, review_case):
    from axiom.access import Authorizer
    from axiom.domains.policies.service import PolicyService
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    for who in ("admin", "auditor"):
        p.bootstrap_role(world.a.id, world[who], "policy_admin", world.a.root, "sla tests")
    definition = {"triage_days": 2, "remediation_days": {"urgent": 1, "high": 3, "medium": 10, "low": 20},
                  "pause_on_deferral": False}
    with db.tenant_tx(ctx_for("admin")) as conn:
        v = PolicyService(conn, ctx_for("admin"), Authorizer(conn, ctx_for("admin"))).draft(
            kind="sla", definition=definition, rationale="tighter targets (provisional)")
    with db.tenant_tx(ctx_for("auditor")) as conn:
        PolicyService(conn, ctx_for("auditor"), Authorizer(conn, ctx_for("auditor"))).publish(v["id"], rationale="ok")
    sweep(db, ctx_for("system"))
    [t] = timers(run, ctx_for("analyst"), review_case)
    assert t["policy_version_id"] == v["id"] and t["due_at"] - t["started_at"] == timedelta(days=2)
    assert t["policy_snapshot"]["provisional"] is True
