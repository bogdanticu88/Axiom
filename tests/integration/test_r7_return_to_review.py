"""R7 (approved 2026-10-22): returning from remediation to review, with the project owner's conditions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.actions.service import ActionService
from axiom.domains.cases.service import EvidenceRef
from axiom.errors import Conflict, ValidationFailed
from axiom.ingestion.sync import SyncService

from .test_cases import DIGEST_NEW, advance_to_review, scenario  # noqa: F401 - fixture

pytestmark = pytest.mark.db


def planned(run, ctx_for, world, sc):
    cid = sc["case"]["id"]
    advance_to_review(run, ctx_for("analyst"), cid, sc["evidence"]["id"])
    run(ctx_for("analyst"), lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"],
                                                               rationale="patch"))
    return cid


def remediating(run, ctx_for, world, sc):
    cid = planned(run, ctx_for, world, sc)
    run(ctx_for("owner"), lambda s: s.cases.record_external_work(cid, 3, external_reference="SEC-9", rationale="go"))
    return cid


def case(run, ctx_for, cid):
    return run(ctx_for("analyst"), lambda s: s.cases.get(cid))


def test_planned_returns_to_review_through_a_recorded_decision(run, ctx_for, world, scenario):  # noqa: F811
    cid = planned(run, ctx_for, world, scenario)
    with pytest.raises(PermissionDenied):      # viewers hold no remediation.propose
        run(ctx_for("viewer"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="no"))
    out = run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="vendor has no fix"))
    assert out["workflow"] == "review_required" and out["plan_epoch"] == 1 and out["disposition"] == "unset"
    hist = run(ctx_for("analyst"), lambda s: s.cases.history(cid))
    last = hist["events"][-1]
    assert last["event_type"] == "case.remediation_withdrawn" and last["from_workflow"] == "remediation_planned"
    decision = run(ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT kind, outcome, rationale FROM axiom.decisions WHERE id = %s", (last["decision_id"],)).fetchone())
    assert decision == {"kind": "remediation_withdrawal", "outcome": "plan_withdrawn",
                        "rationale": "vendor has no fix"}


def test_remediating_returns_directly_only_with_verified_no_change_evidence(run, ctx_for, world, scenario,  # noqa: F811
                                                                           upload):
    cid = remediating(run, ctx_for, world, scenario)
    owner = ctx_for("owner")
    with pytest.raises(ValidationFailed) as err:
        run(owner, lambda s: s.cases.withdraw_remediation(cid, 4, rationale="stopped", deployment_state="none"))
    assert err.value.code == "evidence_required"
    pending = upload(owner, world.a.project, b"change calendar: no deployment", finalise=False)
    with pytest.raises(Conflict):        # unverified evidence cannot support the decision
        run(owner, lambda s: s.cases.withdraw_remediation(cid, 4, rationale="stopped", deployment_state="none",
                                                          evidence=[EvidenceRef(pending["id"])]))
    ev = upload(owner, world.a.project, b"change calendar: no deployment happened")
    out = run(owner, lambda s: s.cases.withdraw_remediation(cid, 4, rationale="stopped before rollout",
                                                            deployment_state="none", evidence=[EvidenceRef(ev["id"])]))
    assert out["workflow"] == "review_required"


def test_database_refuses_a_direct_return_without_evidence(run, ctx_for, world, scenario):  # noqa: F811
    """Bypass the service's evidence check: the database guard on case events still refuses."""
    from axiom.domains.cases import service as svc
    cid = remediating(run, ctx_for, world, scenario)
    real = svc.CaseService.withdraw_remediation

    def no_evidence_check(self, case_id, expected_version, **kw):
        kw["evidence"] = [svc.EvidenceRef(scenario["evidence"]["id"], "context")]   # not "supports"
        case_row = self._load(case_id)
        return self._apply(case_row, expected_version, svc._Plan(
            to_workflow=svc.Workflow.REVIEW, event_type="case.remediation_withdrawn",
            decision_kind="remediation_withdrawal", decision_outcome="no_change_deployed", rationale="bypass",
            authority=self.authz.require("remediation.propose", case_row["scope_id"]), evidence=kw["evidence"]))
    svc.CaseService.withdraw_remediation = no_evidence_check
    try:
        with pytest.raises(psycopg.errors.CheckViolation, match="verified evidence that no change"):
            run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 4, rationale="x"))
    finally:
        svc.CaseService.withdraw_remediation = real


@pytest.mark.parametrize("state", ["deployed", "partial", "unknown"])
def test_deployed_partial_or_unknown_goes_through_verification(run, ctx_for, world, scenario, state):  # noqa: F811
    cid = remediating(run, ctx_for, world, scenario)
    owner = ctx_for("owner")
    with pytest.raises(ValidationFailed):          # cannot take the direct route without saying nothing deployed
        run(owner, lambda s: s.cases.withdraw_remediation(cid, 4, rationale="x", deployment_state=None))
    target = None if state == "unknown" else scenario["new"]["id"]
    out = run(owner, lambda s: s.cases.withdraw_remediation(cid, 4, rationale="abandoned midway",
                                                            deployment_state=state, target_asset_version_id=target))
    assert out["workflow"] == "awaiting_verification"
    claimed = "failed" if state == "partial" else "passed"
    verified = run(ctx_for("analyst2"), lambda s: s.cases.record_verification(
        cid, 5, claimed_result=claimed, coverage="complete", criteria={"package": "openssl"},
        observed_deployment_digest=DIGEST_NEW if state != "unknown" else None, rationale="checked"))
    if state == "unknown":
        assert verified["workflow"] == "review_required"            # always inconclusive: nothing to verify
    elif state == "partial":
        assert verified["workflow"] == "review_required"            # failed on an abandoned plan -> review
    else:
        assert verified["workflow"] == "review_required"            # pass without verified evidence: inconclusive


def test_unresolved_external_effects_block_every_route(run, ctx_for, world, scenario, db, dbinfo, admin_conn):  # noqa: F811
    from axiom.provisioning import Provisioner
    cid = planned(run, ctx_for, world, scenario)
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "t")
    connection = SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="jira_style", scope_id=world.a.project, display_name="t",
        base_url="https://tracker.test.invalid", credential_ref="secretref:test/t", config={})

    def svc(who, fn):
        ctx = ctx_for(who)
        with db.tenant_tx(ctx) as conn:
            return fn(ActionService(conn, ctx, Authorizer(conn, ctx)))
    p = svc("analyst", lambda s: s.propose(case_id=cid, effect="ticket.create", connection_id=connection["id"],
                                           payload={"project_key": "SEC", "summary": "patch"},
                                           verification_criteria="exists",
                                           expires_at=datetime.now(timezone.utc) + timedelta(days=3)))
    a = svc("approver", lambda s: s.decide(p["id"], 1, decision="approved", rationale="ok", max_uses=2))
    e = svc("analyst", lambda s: s.request_execution(p["id"], 1, a["id"]))            # prepared, not yet run
    with pytest.raises(Conflict) as err:
        run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="abandon"))
    assert err.value.code == "unresolved_external_effect"
    # simulate the execution reaching the provider and becoming uncertain: still blocked
    admin_conn.execute("UPDATE axiom.action_executions SET state = 'reconciling', record_version = record_version + 1 "
                       "WHERE id = %s", (e["id"],))
    with pytest.raises(Conflict):
        run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="abandon"))
    # resolve it (operator abandons the effect, which keeps the use consumed), then withdraw
    admin_conn.execute("UPDATE axiom.action_executions SET state = 'failed', record_version = record_version + 1 "
                       "WHERE id = %s", (e["id"],))
    out = run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="abandon"))
    assert out["workflow"] == "review_required"
    after = svc("analyst", lambda s: s.get(p["id"]))
    assert after["status"] == "withdrawn"                                          # obsolete plan withdrawn
    assert after["approvals"][0]["status"] == "active"                             # approvals preserved ...
    assert after["approvals"][0]["uses_reserved"] == 1                             # ... and no use restored
    assert len(after["executions"]) == 1                                           # history preserved
    with pytest.raises(Conflict):                                                  # cannot execute any more
        svc("analyst", lambda s: s.request_execution(p["id"], 1, a["id"]))


def test_database_refuses_leaving_remediation_with_an_unresolved_effect(run, ctx_for, world, scenario, db,  # noqa: F811
                                                                       dbinfo, admin_conn):
    """Service check bypassed: the case-event guard refuses while an execution is unresolved."""
    from axiom.domains.cases import service as svc
    from axiom.provisioning import Provisioner
    cid = planned(run, ctx_for, world, scenario)
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "t")
    connection = SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="jira_style", scope_id=world.a.project, display_name="t",
        base_url="https://tracker.test.invalid", credential_ref="secretref:test/t", config={})
    ctx = ctx_for("analyst")
    with db.tenant_tx(ctx) as conn:
        p = ActionService(conn, ctx, Authorizer(conn, ctx)).propose(
            case_id=cid, effect="ticket.create", connection_id=connection["id"],
            payload={"project_key": "SEC", "summary": "patch"}, verification_criteria="exists",
            expires_at=datetime.now(timezone.utc) + timedelta(days=3))
    actx = ctx_for("approver")
    with db.tenant_tx(actx) as conn:
        a = ActionService(conn, actx, Authorizer(conn, actx)).decide(p["id"], 1, decision="approved", rationale="ok")
    with db.tenant_tx(ctx) as conn:
        ActionService(conn, ctx, Authorizer(conn, ctx)).request_execution(p["id"], 1, a["id"])
    real = svc.CaseService.withdraw_remediation

    def skip_effect_check(self, case_id, expected_version, **kw):
        case_row = self._load(case_id)
        return self._apply(case_row, expected_version, svc._Plan(
            to_workflow=svc.Workflow.REVIEW, event_type="case.remediation_withdrawn",
            decision_kind="remediation_withdrawal", decision_outcome="plan_withdrawn", rationale="bypass",
            authority=self.authz.require("remediation.propose", case_row["scope_id"])))
    svc.CaseService.withdraw_remediation = skip_effect_check
    try:
        with pytest.raises(psycopg.errors.CheckViolation, match="unresolved external effect"):
            run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="x"))
    finally:
        svc.CaseService.withdraw_remediation = real


def test_proposal_from_a_withdrawn_plan_cannot_execute_even_if_reopened(run, ctx_for, world, scenario, db,  # noqa: F811
                                                                         dbinfo, admin_conn):
    """Plan epoch: a proposal created before the withdrawal is obsolete even if somehow still open."""
    from axiom.domains.actions.service import precondition_failures
    cid = planned(run, ctx_for, world, scenario)
    before = case(run, ctx_for, cid)
    version = {"preconditions": {"case_open": True, "case_priority": before["priority"],
                                 "plan_epoch": before["plan_epoch"]}, "scope_id": before["scope_id"]}
    assert precondition_failures(before, version) == []
    run(ctx_for("analyst"), lambda s: s.cases.withdraw_remediation(cid, 3, rationale="new plan needed"))
    run(ctx_for("analyst"), lambda s: s.cases.plan_remediation(cid, 4, owner_principal_id=world["owner"],
                                                               rationale="second plan"))
    after = case(run, ctx_for, cid)
    assert after["workflow"] == "remediation_planned"                 # same state as before ...
    assert any("plan was withdrawn" in f for f in precondition_failures(after, version))   # ... but obsolete


def test_linked_work_and_evidence_are_kept(run, ctx_for, world, scenario):  # noqa: F811
    cid = remediating(run, ctx_for, world, scenario)

    def snapshot():
        return run(ctx_for("analyst"), lambda s: {
            "external_work": s.conn.execute("SELECT count(*) AS n FROM axiom.decisions WHERE case_id = %s "
                                            "AND kind = 'external_work'", (cid,)).fetchone()["n"],
            "evidence": s.conn.execute("SELECT count(*) AS n FROM axiom.decision_evidence de JOIN axiom.decisions d "
                                       "ON d.id = de.decision_id WHERE d.case_id = %s", (cid,)).fetchone()["n"],
            "links": s.conn.execute("SELECT count(*) AS n FROM axiom.case_occurrence_links WHERE case_id = %s "
                                    "AND unlinked_at IS NULL", (cid,)).fetchone()["n"]})
    before = snapshot()
    assert before["external_work"] == 1
    run(ctx_for("owner"), lambda s: s.cases.withdraw_remediation(cid, 4, rationale="abandon",
                                                                 deployment_state="unknown"))
    assert snapshot() == before            # nothing about the earlier work, evidence or links was removed
    topics = run(ctx_for("analyst"), lambda s: [r["topic"] for r in s.conn.execute(
        "SELECT topic FROM axiom.outbox WHERE aggregate_id = %s", (cid,))])
    assert topics and all(t == "case.transitioned" or t.startswith("case.") for t in topics)
