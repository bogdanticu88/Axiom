"""Two-step risk acceptance (RISK-02): request, independent authorisation, stale requests, renewal, reassessment."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.domains.cases.risk import RiskService, risk_sweep
from axiom.domains.cases.service import EvidenceRef, expire_risk_acceptances
from axiom.errors import Conflict, Forbidden

pytestmark = pytest.mark.db


def now(**kw):
    return datetime.now(timezone.utc) + timedelta(**kw)


@pytest.fixture()
def review_case(world, run, ctx_for, upload):
    """A case in review (version 2), plus delegation limits for risk_owner (urgent, 90 days)."""
    analyst = ctx_for("analyst")
    case = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="exposed admin panel"))
    ev = upload(analyst, world.a.project, b"scan: admin panel reachable")
    run(analyst, lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(case["id"], 1, assessment="supported", rationale="confirmed",
                                                      limitations="none", evidence=[EvidenceRef(ev["id"])]))
    run(ctx_for("admin"), lambda s: s.tenancy.set_delegation_limit(
        principal_id=world["risk_owner"], action_class="risk.accept", scope_id=world.a.project,
        max_priority="urgent", max_duration_days=90))
    return case["id"]


def risk(run, ctx, fn):
    return run(ctx, lambda s: fn(RiskService(s.conn, ctx, s.authz)))


def set_priority(run, ctx_for, case_id, priority, version):
    """Override the case priority through the supported command."""
    from axiom.domains.cases import priority as prio
    return run(ctx_for("analyst"), lambda s: prio.override(s.cases, case_id, version, priority=priority,
                                                           rationale="business owner rated this low impact"))


def test_high_impact_needs_someone_other_than_the_requester(run, ctx_for, review_case, admin_conn):
    owner = ctx_for("risk_owner")
    req = risk(run, owner, lambda r: r.request(review_case, 2, expires_at=now(days=30), rationale="mitigated"))
    assert req["independent_required"] and "priority pending" in req["policy"]["reasons"][0]
    with pytest.raises(Forbidden) as err:
        risk(run, owner, lambda r: r.authorise(req["id"], rationale="self"))
    assert err.value.code == "independent_authorisation_required"
    with pytest.raises(Conflict) as err:                        # one pending request per case
        risk(run, owner, lambda r: r.request(review_case, 2, expires_at=now(days=20), rationale="again"))
    assert err.value.code == "request_pending"
    risk(run, owner, lambda r: r.withdraw(req["id"], reason="use the single-call path"))
    with pytest.raises(Forbidden) as err:                       # the single-call path refuses too
        run(owner, lambda s: s.cases.accept_risk(review_case, 2, expires_at=now(days=30), rationale="self"))
    assert err.value.code == "independent_authorisation_required"


def test_database_backstop_for_independence(run, ctx_for, review_case, world, upload):
    analyst, owner = ctx_for("analyst"), ctx_for("risk_owner")
    req = risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(days=30), rationale="x"))
    done = risk(run, owner, lambda r: r.authorise(req["id"], rationale="ok"))
    other = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="second"))
    ev = upload(analyst, world.a.project, b"scan 2")
    run(analyst, lambda s: s.cases.start_investigation(other["id"], 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(other["id"], 1, assessment="supported", rationale="x",
                                                      limitations="none", evidence=[EvidenceRef(ev["id"])]))
    req2 = risk(run, owner, lambda r: r.request(other["id"], 2, expires_at=now(days=30), rationale="self"))
    with pytest.raises(psycopg.errors.CheckViolation):
        run(owner, lambda s: s.conn.execute(
            """UPDATE axiom.risk_acceptance_requests SET status = 'authorised', decided_by = requested_by,
                      decided_at = now(), acceptance_id = %s, record_version = record_version + 1 WHERE id = %s""",
            (done["acceptance_id"], req2["id"])))


def test_low_impact_short_acceptance_can_be_self_authorised(run, ctx_for, review_case, admin_conn):
    set_priority(run, ctx_for, review_case, "low", 2)
    owner = ctx_for("risk_owner")
    with pytest.raises(Forbidden) as err:                       # long duration still needs independence
        run(owner, lambda s: s.cases.accept_risk(review_case, 3, expires_at=now(days=120), rationale="long"))
    assert err.value.code == "independent_authorisation_required"   # the refused call left no request behind
    closed = run(owner, lambda s: s.cases.accept_risk(review_case, 3, expires_at=now(days=30), rationale="minor"))
    assert closed["workflow"] == "closed"


def test_request_goes_stale_when_the_case_changes(run, ctx_for, review_case, upload, world):
    analyst, owner = ctx_for("analyst"), ctx_for("risk_owner")
    req = risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(days=30), rationale="x"))
    run(analyst, lambda s: s.cases.request_more_evidence(review_case, 2, "need exploitability data"))
    with pytest.raises(Conflict) as err:
        risk(run, owner, lambda r: r.authorise(req["id"], rationale="ok"))
    assert err.value.code == "request_stale"


def test_renewal_supersedes_and_expiry_follows_the_chain(run, ctx_for, review_case):
    analyst, owner, system = ctx_for("analyst"), ctx_for("risk_owner"), ctx_for("system")
    req = risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(seconds=4), rationale="short"))
    first = risk(run, owner, lambda r: r.authorise(req["id"], rationale="ok"))
    with pytest.raises(Conflict):                                   # a second "new" request on a closed case
        risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(seconds=3), rationale="x"))
    ren = risk(run, analyst, lambda r: r.request(review_case, 3, expires_at=now(seconds=8), rationale="extend"))
    assert ren["kind"] == "renewal" and ren["renewal_of"] == first["acceptance_id"]
    second = risk(run, owner, lambda r: r.authorise(ren["id"], rationale="extended"))
    rows = run(analyst, lambda s: {r["id"]: r for r in s.conn.execute(
        "SELECT * FROM axiom.risk_acceptances WHERE case_id = %s", (review_case,))})
    assert rows[first["acceptance_id"]]["status"] == "superseded"
    assert rows[second["acceptance_id"]]["status"] == "active"
    time.sleep(4.5)                                                  # the original's expiry passes: nothing happens
    assert run(system, lambda s: expire_risk_acceptances(s.conn, system, s.authz)) == []
    assert run(analyst, lambda s: s.cases.get(review_case))["workflow"] == "closed"
    time.sleep(4.0)                                                  # the renewal expires: the case reopens
    assert run(system, lambda s: expire_risk_acceptances(s.conn, system, s.authz)) == [second["acceptance_id"]]
    assert run(analyst, lambda s: s.cases.get(review_case))["workflow"] == "investigating"


def test_reassessment_notice_once_and_requests_lapse(run, ctx_for, review_case, world, upload):
    analyst, owner, system = ctx_for("analyst"), ctx_for("risk_owner"), ctx_for("system")
    req = risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(days=10), rationale="x"))
    accepted = risk(run, owner, lambda r: r.authorise(req["id"], rationale="ok"))
    first = run(system, lambda s: risk_sweep(s.conn, system, s.authz))
    second = run(system, lambda s: risk_sweep(s.conn, system, s.authz))
    assert accepted["acceptance_id"] in first["reassessment_notices"] and second["reassessment_notices"] == []
    note = run(analyst, lambda s: s.conn.execute(
        "SELECT payload FROM axiom.outbox WHERE topic = 'risk_acceptance.reassessment_due' AND aggregate_id = %s",
        (accepted["acceptance_id"],)).fetchone())
    assert note["payload"]["notify_principal_id"] == str(world["risk_owner"])
    # lapse: a request that nobody decides before it lapses cannot be authorised later
    other = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="third"))
    ev = upload(analyst, world.a.project, b"scan 3")
    run(analyst, lambda s: s.cases.start_investigation(other["id"], 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(other["id"], 1, assessment="supported", rationale="x",
                                                      limitations="none", evidence=[EvidenceRef(ev["id"])]))
    short = risk(run, analyst, lambda r: r.request(other["id"], 2, expires_at=now(seconds=2), rationale="x"))
    time.sleep(2.5)
    assert short["id"] in run(system, lambda s: risk_sweep(s.conn, system, s.authz))["lapsed"]
    with pytest.raises(Conflict) as err:
        risk(run, owner, lambda r: r.authorise(short["id"], rationale="late"))
    assert err.value.code == "request_not_pending"


def test_request_terms_are_immutable(run, ctx_for, review_case):
    analyst = ctx_for("analyst")
    req = risk(run, analyst, lambda r: r.request(review_case, 2, expires_at=now(days=30), rationale="x"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run(analyst, lambda s: s.conn.execute(
            "UPDATE axiom.risk_acceptance_requests SET requested_expires_at = now() + interval '300 days', "
            "record_version = record_version + 1 WHERE id = %s", (req["id"],)))
