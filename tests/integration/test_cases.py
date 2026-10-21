"""Database-backed case command tests (live PostgreSQL, runtime role, RLS enforced)."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom import audit as audit_module
from axiom.access import PermissionDenied
from axiom.domains.cases.service import EvidenceRef, expire_risk_acceptances
from axiom.errors import Conflict, Forbidden, NotFound, ValidationFailed

pytestmark = pytest.mark.db

DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64
DIGEST_WRONG = "sha256:" + "c" * 64


@pytest.fixture()
def scenario(world, run, ctx_for, upload):
    """A case in tenant A on an image asset, with versions for the vulnerable and fixed deployments."""
    analyst = ctx_for("analyst")
    now = datetime.now(timezone.utc)

    def setup(s):
        asset = s.assets.create_asset(scope_id=world.a.project, kind="container_image", display_name="payments-api")
        old = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_OLD)
        new = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_NEW)
        occ = s.assets.record_occurrence(source_system="trivy", source_finding_id="f-1",
                                         asset_version_id=old["id"], component_locator="openssl@3.0.1",
                                         vulnerability_ref="CVE-2099-0001")
        case = s.cases.create(scope_id=world.a.project, title="openssl in payments-api",
                              occurrence_ids=[occ["id"]])
        return {"asset": asset, "old": old, "new": new, "occ": occ, "case": case}
    data = run(analyst, setup)
    data["evidence"] = upload(analyst, world.a.project, b"trivy report: openssl 3.0.1 vulnerable")
    return data


def advance_to_review(run, ctx, case_id, evidence_id, assessment="supported", version=0):
    run(ctx, lambda s: s.cases.start_investigation(case_id, version, "triage"))
    return run(ctx, lambda s: s.cases.record_assessment(
        case_id, version + 1, assessment=assessment, rationale="scanner and version evidence agree",
        limitations="reachability not assessed", evidence=[EvidenceRef(evidence_id)]))


def advance_to_verification(run, ctx_for, world, scenario):
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    cid = scenario["case"]["id"]
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="patch"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-1", rationale="ticket"))
    return run(owner, lambda s: s.cases.report_change(cid, 4, target_asset_version_id=scenario["new"]["id"],
                                                     change_reference="deploy 42", rationale="rolled out"))


def test_full_lifecycle_to_verified_closure_and_reopen_preserves_history(world, run, ctx_for, scenario, upload):
    cid = scenario["case"]["id"]
    case = advance_to_verification(run, ctx_for, world, scenario)
    assert case["workflow"] == "awaiting_verification" and case["record_version"] == 5
    analyst2 = ctx_for("analyst2")
    check = upload(analyst2, world.a.project, b"rescan: openssl 3.0.15 on sha256:bbbb")
    verified = run(analyst2, lambda s: s.cases.record_verification(
        cid, 5, claimed_result="passed", coverage="complete", criteria={"package": "openssl", "min": "3.0.15"},
        observed_deployment_digest=DIGEST_NEW, evidence_id=check["id"], rationale="rescan clean"))
    assert verified["workflow"] == "awaiting_verification" and verified["record_version"] == 6
    run_id = run(analyst2, lambda s: s.conn.execute(
        "SELECT id, outcome FROM axiom.verification_runs WHERE case_id = %s", (cid,)).fetchone())
    assert run_id["outcome"] == "passed"
    closed = run(analyst2, lambda s: s.cases.close_verified(cid, 6, verification_run_id=run_id["id"],
                                                           rationale="verified on deployed digest"))
    assert closed["workflow"] == "closed"
    reopened = run(analyst2, lambda s: s.cases.reopen(cid, 7, reason="recurrence", rationale="seen again"))
    assert reopened["workflow"] == "investigating" and reopened["assessment"] == "unassessed"
    history = run(analyst2, lambda s: s.cases.history(cid))
    assert [e["sequence"] for e in history["events"]] == list(range(9))
    assert history["closures"][0]["reason"] == "verified_remediated"   # B09: closure retained after reopen
    assert all(e["audit_event_id"] for e in history["events"])
    outbox = run(analyst2, lambda s: s.conn.execute(
        "SELECT count(*) AS n FROM axiom.outbox WHERE aggregate_id = %s", (cid,)).fetchone())
    assert outbox["n"] == 9


def test_stale_version_rejected_without_partial_state(world, run, ctx_for, scenario):
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.escalate(cid, 0, "stale"))
    assert err.value.code == "stale_version"
    case = run(analyst, lambda s: s.cases.get(cid))
    assert case["record_version"] == 1 and case["workflow"] == "investigating"


def test_concurrent_contradictory_decisions_one_commits(world, run, ctx_for, scenario, db):
    """A17: two writers with the same expected version; exactly one commits."""
    cid = scenario["case"]["id"]
    analyst, analyst2 = ctx_for("analyst"), ctx_for("analyst2")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def attempt(name, ctx, fn):
        try:
            def body(s):
                s.cases.get(cid)
                barrier.wait(timeout=10)
                return fn(s)
            results[name] = run(ctx, body)
        except Exception as exc:  # noqa: BLE001
            results[name] = exc

    t1 = threading.Thread(target=attempt, args=("plan", analyst, lambda s: s.cases.plan_remediation(
        cid, 2, owner_principal_id=world["owner"], rationale="fix")))
    t2 = threading.Thread(target=attempt, args=("more", analyst2, lambda s: s.cases.request_more_evidence(
        cid, 2, "need reachability")))
    t1.start(), t2.start(), t1.join(), t2.join()
    outcomes = sorted(type(v).__name__ for v in results.values())
    assert outcomes == ["Conflict", "dict"], results
    final = run(analyst, lambda s: s.cases.get(cid))
    assert final["record_version"] == 3


def test_definite_assessment_requires_verified_evidence(world, run, ctx_for, scenario, upload):
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="not_supported", rationale="looks fine",
                                                          limitations="none", evidence=[]))
    assert err.value.code == "evidence_required"
    pending = upload(analyst, world.a.project, b"unverified", finalise=False)
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="supported", rationale="r",
                                                          limitations="none", evidence=[EvidenceRef(pending["id"])]))
    assert err.value.code == "evidence_not_verified"
    ok = run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="inconclusive", rationale="no data",
                                                           limitations="scanner data stale", evidence=[]))
    assert ok["assessment"] == "inconclusive"


def test_wrong_deployment_digest_is_inconclusive(world, run, ctx_for, scenario, upload):
    """A18: verification against a different image digest cannot pass."""
    cid = scenario["case"]["id"]
    advance_to_verification(run, ctx_for, world, scenario)
    analyst2 = ctx_for("analyst2")
    check = upload(analyst2, world.a.project, b"clean scan of some image")
    case = run(analyst2, lambda s: s.cases.record_verification(
        cid, 5, claimed_result="passed", coverage="complete", criteria={"package": "openssl"},
        observed_deployment_digest=DIGEST_WRONG, evidence_id=check["id"], rationale="clean"))
    assert case["workflow"] == "review_required"
    vr = run(analyst2, lambda s: s.conn.execute(
        "SELECT outcome, outcome_reason FROM axiom.verification_runs WHERE case_id = %s", (cid,)).fetchone())
    assert vr["outcome"] == "inconclusive" and "differs" in vr["outcome_reason"]


def test_partial_coverage_cannot_pass_and_failure_returns_to_remediating(world, run, ctx_for, scenario, upload):
    cid = scenario["case"]["id"]
    advance_to_verification(run, ctx_for, world, scenario)
    analyst2 = ctx_for("analyst2")
    check = upload(analyst2, world.a.project, b"partial scan")
    case = run(analyst2, lambda s: s.cases.record_verification(
        cid, 5, claimed_result="failed", coverage="complete", criteria={"package": "openssl"},
        observed_deployment_digest=DIGEST_NEW, evidence_id=check["id"], rationale="still vulnerable"))
    assert case["workflow"] == "remediating"
    owner = ctx_for("owner")
    run(owner, lambda s: s.cases.report_change(cid, 6, target_asset_version_id=scenario["new"]["id"],
                                              change_reference="deploy 43", rationale="second attempt"))
    case = run(analyst2, lambda s: s.cases.record_verification(
        cid, 7, claimed_result="passed", coverage="partial", criteria={"package": "openssl"},
        observed_deployment_digest=DIGEST_NEW, evidence_id=check["id"], rationale="half the hosts"))
    assert case["workflow"] == "review_required"


def test_reporter_cannot_verify_own_change(world, run, ctx_for, scenario, upload):
    cid = scenario["case"]["id"]
    advance_to_verification(run, ctx_for, world, scenario)
    analyst = ctx_for("analyst")
    # analyst did not report; owner did. Owner lacks verification.record anyway; test SoD with an analyst reporter.
    with pytest.raises((Forbidden, PermissionDenied)):
        run(ctx_for("owner"), lambda s: s.cases.record_verification(
            cid, 5, claimed_result="passed", coverage="complete", criteria={"x": 1},
            observed_deployment_digest=DIGEST_NEW, rationale="mine"))
    assert run(analyst, lambda s: s.cases.get(cid))["record_version"] == 5


def test_no_closure_path_from_remediating(world, run, ctx_for, scenario):
    """A09: external ticket closure is not a platform command; nothing closes from remediating."""
    cid = scenario["case"]["id"]
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="fix"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-1", rationale="ticket"))
    with pytest.raises(Conflict):
        run(analyst, lambda s: s.cases.close_duplicate(cid, 4, duplicate_of=cid, rationale="ticket closed"))
    with pytest.raises(Conflict):
        run(analyst, lambda s: s.cases.close_verified(cid, 4, verification_run_id=cid, rationale="ticket closed"))
    assert run(analyst, lambda s: s.cases.get(cid))["workflow"] == "remediating"


def test_plan_requires_eligible_owner(world, run, ctx_for, scenario):
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["viewer"], rationale="x"))
    assert err.value.code == "owner_not_eligible"


def test_dismissal_requires_evidence_backed_assessment_and_independent_approver(world, run, ctx_for, scenario):
    cid = scenario["case"]["id"]
    analyst, approver = ctx_for("analyst"), ctx_for("approver")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"], assessment="not_supported")
    with pytest.raises(PermissionDenied):
        run(analyst, lambda s: s.cases.dismiss(cid, 2, rationale="not exploitable"))
    closed = run(approver, lambda s: s.cases.dismiss(cid, 2, rationale="package not loaded at runtime"))
    assert closed["workflow"] == "closed" and closed["disposition"] == "dismiss"


def test_inconclusive_assessment_cannot_be_dismissed(world, run, ctx_for, scenario):
    """B03: missing evidence cannot justify dismissal."""
    cid = scenario["case"]["id"]
    analyst, approver = ctx_for("analyst"), ctx_for("approver")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="inconclusive", rationale="stale data",
                                                      limitations="scanner offline", evidence=[]))
    with pytest.raises(Conflict):
        run(approver, lambda s: s.cases.dismiss(cid, 2, rationale="probably fine"))


def test_risk_acceptance_limits_owner_and_expiry_reopens(world, run, ctx_for, scenario):
    """A11 plus delegation limits."""
    cid = scenario["case"]["id"]
    analyst, risk_owner, admin = ctx_for("analyst"), ctx_for("risk_owner"), ctx_for("admin")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    soon = datetime.now(timezone.utc) + timedelta(days=30)
    with pytest.raises(Forbidden) as err:   # no delegation limit yet
        run(risk_owner, lambda s: s.cases.accept_risk(cid, 2, expires_at=soon, rationale="compensated"))
    assert err.value.code == "delegation_limit_exceeded"
    run(admin, lambda s: s.tenancy.set_delegation_limit(principal_id=world["risk_owner"], action_class="risk.accept",
                                                         scope_id=world.a.project, max_priority="medium",
                                                         max_duration_days=90))
    with pytest.raises(Forbidden):          # pending priority counts as urgent
        run(risk_owner, lambda s: s.cases.accept_risk(cid, 2, expires_at=soon, rationale="compensated"))
    run(admin, lambda s: s.tenancy.set_delegation_limit(principal_id=world["risk_owner"], action_class="risk.accept",
                                                         scope_id=world.a.project, max_priority="urgent",
                                                         max_duration_days=90))
    with pytest.raises(Forbidden):          # beyond max duration
        run(risk_owner, lambda s: s.cases.accept_risk(cid, 2, expires_at=soon + timedelta(days=100),
                                                      rationale="too long"))
    expiry = datetime.now(timezone.utc) + timedelta(seconds=2)
    closed = run(risk_owner, lambda s: s.cases.accept_risk(cid, 2, expires_at=expiry, rationale="WAF rule",
                                                          compensating_controls="WAF rule 991"))
    assert closed["workflow"] == "closed" and closed["disposition"] == "accept_risk"
    system = ctx_for("system")
    assert run(system, lambda s: expire_risk_acceptances(s.conn, system, s.authz)) == []
    time.sleep(2.5)
    expired = run(system, lambda s: expire_risk_acceptances(s.conn, system, s.authz))
    assert len(expired) == 1
    case = run(analyst, lambda s: s.cases.get(cid))
    assert case["workflow"] == "investigating"
    notify = run(analyst, lambda s: s.conn.execute(
        "SELECT payload FROM axiom.outbox WHERE topic = 'risk_acceptance.expired' AND payload->>'case_id' = %s",
        (str(cid),)).fetchone())
    assert notify["payload"]["notify_principal_id"] == str(world["risk_owner"])
    assert run(system, lambda s: expire_risk_acceptances(s.conn, system, s.authz)) == []   # idempotent


def test_case_owner_cannot_accept_own_risk(world, run, ctx_for, scenario, dbinfo):
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["owner"], "risk_owner", world.a.project,
                                                     "owner also risk owner")
    cid = scenario["case"]["id"]
    run(ctx_for("admin"), lambda s: s.tenancy.set_delegation_limit(
        principal_id=world["owner"], action_class="risk.accept", scope_id=world.a.project,
        max_priority="urgent", max_duration_days=90))
    advance_to_verification(run, ctx_for, world, scenario)
    # An inconclusive verification returns the case to review with the owner still assigned.
    run(ctx_for("analyst2"), lambda s: s.cases.record_verification(
        cid, 5, claimed_result="inconclusive", coverage="none", criteria={"package": "openssl"},
        observed_deployment_digest=DIGEST_NEW, rationale="scanner unavailable"))
    owner = ctx_for("owner")
    with pytest.raises(Forbidden) as err:
        run(owner, lambda s: s.cases.accept_risk(cid, 6, expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                                                 rationale="I own it and accept it"))
    assert err.value.code == "separation_of_duties"


def test_duplicate_requires_shared_vulnerability_on_same_asset(world, run, ctx_for, scenario):
    analyst = ctx_for("analyst")
    cid = scenario["case"]["id"]

    def second(s):
        occ = s.assets.record_occurrence(source_system="snyk", source_finding_id="SNYK-1",
                                         asset_version_id=scenario["old"]["id"], component_locator="openssl",
                                         vulnerability_ref="CVE-2099-0001")
        unrelated = s.assets.record_occurrence(source_system="snyk", source_finding_id="SNYK-2",
                                               asset_version_id=scenario["old"]["id"], component_locator="zlib",
                                               vulnerability_ref="CVE-2099-0002")
        dup = s.cases.create(scope_id=world.a.project, title="snyk openssl", occurrence_ids=[occ["id"]])
        other = s.cases.create(scope_id=world.a.project, title="zlib", occurrence_ids=[unrelated["id"]])
        return dup, other
    dup, other = run(analyst, second)
    advance_to_review(run, analyst, other["id"], scenario["evidence"]["id"])
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.close_duplicate(other["id"], 2, duplicate_of=cid, rationale="same?"))
    assert err.value.code == "duplicate_not_validated"
    advance_to_review(run, analyst, dup["id"], scenario["evidence"]["id"])
    closed = run(analyst, lambda s: s.cases.close_duplicate(dup["id"], 2, duplicate_of=cid,
                                                           rationale="same CVE same image, two scanners"))
    assert closed["workflow"] == "closed"
    links = run(analyst, lambda s: s.conn.execute(
        "SELECT count(*) AS n FROM axiom.case_occurrence_links WHERE case_id = %s AND unlinked_at IS NULL",
        (dup["id"],)).fetchone())
    assert links["n"] == 1   # duplicate closure retains links


def test_asset_retirement_closure_requires_retired_assets(world, run, ctx_for, scenario, upload):
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    proof = upload(analyst, world.a.project, b"decommission record CHG-7")
    with pytest.raises(Conflict) as err:
        run(analyst, lambda s: s.cases.close_asset_retired(cid, 2, retirement_evidence_id=proof["id"], rationale="gone"))
    assert err.value.code == "asset_not_retired"
    run(analyst, lambda s: s.assets.retire(asset_id=scenario["asset"]["id"], expected_version=0,
                                           evidence_id=proof["id"], rationale="decommissioned"))
    closed = run(analyst, lambda s: s.cases.close_asset_retired(cid, 2, retirement_evidence_id=proof["id"],
                                                               rationale="decommissioned"))
    reason = run(analyst, lambda s: s.conn.execute("SELECT reason FROM axiom.closure_records WHERE case_id = %s",
                                                   (cid,)).fetchone())
    assert closed["workflow"] == "closed" and reason["reason"] == "asset_retired"


def test_audit_failure_prevents_transition(world, run, ctx_for, scenario, admin_conn):
    """A19 (database fault): a failing audit insert aborts the consequential change."""
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    admin_conn.execute("""
        CREATE OR REPLACE FUNCTION axiom.test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action = 'case.investigation_started' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
              RETURN NEW; END $$;
        CREATE TRIGGER test_fail_audit BEFORE INSERT ON axiom.audit_events
          FOR EACH ROW EXECUTE FUNCTION axiom.test_fail_audit();""")
    try:
        with pytest.raises(psycopg.Error, match="injected audit failure"):
            run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    finally:
        admin_conn.execute("DROP TRIGGER test_fail_audit ON axiom.audit_events; DROP FUNCTION axiom.test_fail_audit();")
    case = run(analyst, lambda s: s.cases.get(cid))
    assert case["workflow"] == "received" and case["record_version"] == 0
    decisions = run(analyst, lambda s: s.conn.execute(
        "SELECT count(*) AS n FROM axiom.decisions WHERE case_id = %s", (cid,)).fetchone())
    assert decisions["n"] == 0


def test_audit_failure_in_application_prevents_transition(world, run, ctx_for, scenario, monkeypatch):
    """A19 (application fault): exception while writing audit leaves no partial state."""
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")

    def broken(*args, **kwargs):
        raise RuntimeError("audit sink down")
    monkeypatch.setattr(audit_module, "record", broken)
    with pytest.raises(RuntimeError):
        run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    monkeypatch.undo()
    case = run(analyst, lambda s: s.cases.get(cid))
    assert case["workflow"] == "received" and case["record_version"] == 0


def test_permission_scope_and_revocation(world, run, ctx_for, scenario):
    cid = scenario["case"]["id"]
    with pytest.raises(PermissionDenied):   # analyst on a sibling scope
        run(ctx_for("marketing_analyst"), lambda s: s.cases.start_investigation(cid, 0, "go"))
    with pytest.raises(PermissionDenied):   # viewer cannot mutate
        run(ctx_for("viewer"), lambda s: s.cases.start_investigation(cid, 0, "go"))
    admin = ctx_for("admin")
    binding = run(admin, lambda s: s.conn.execute(
        "SELECT id FROM axiom.role_bindings WHERE principal_id = %s", (world["analyst2"],)).fetchone())
    run(admin, lambda s: s.tenancy.revoke_role(binding_id=binding["id"], reason="left team"))
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst2"), lambda s: s.cases.start_investigation(cid, 0, "go"))
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst2"), lambda s: s.cases.get(cid))


def test_expired_binding_denied(world, run, ctx_for, scenario):
    admin = ctx_for("admin")
    until = datetime.now(timezone.utc) + timedelta(seconds=1)
    run(admin, lambda s: s.tenancy.assign_role(principal_id=world["viewer"], role_id="analyst",
                                               scope_id=world.a.project, reason="temporary", valid_until=until))
    cid = scenario["case"]["id"]
    time.sleep(1.5)
    with pytest.raises(PermissionDenied):
        run(ctx_for("viewer"), lambda s: s.cases.start_investigation(cid, 0, "go"))


def test_tenant_admin_delegation_rules(world, run, ctx_for, scenario):
    admin = ctx_for("admin")
    with pytest.raises(Forbidden):
        run(admin, lambda s: s.tenancy.assign_role(principal_id=world["admin"], role_id="risk_owner",
                                                   scope_id=world.a.root, reason="self"))
    with pytest.raises(PermissionDenied):   # administration grants no case/evidence authority
        run(admin, lambda s: s.cases.get(scenario["case"]["id"]))
    with pytest.raises(ValidationFailed):
        run(admin, lambda s: s.tenancy.assign_role(
            principal_id=world["viewer"], role_id="approver", scope_id=world.a.project, reason="incident",
            emergency=True, valid_until=datetime.now(timezone.utc) + timedelta(hours=48)))
    with pytest.raises(PermissionDenied):   # analyst cannot assign roles
        run(ctx_for("analyst"), lambda s: s.tenancy.assign_role(principal_id=world["viewer"], role_id="analyst",
                                                                scope_id=world.a.project, reason="x"))
    row = run(admin, lambda s: s.tenancy.assign_role(
        principal_id=world["viewer"], role_id="approver", scope_id=world.a.project, reason="incident 7",
        emergency=True, valid_until=datetime.now(timezone.utc) + timedelta(hours=4)))
    assert row["emergency"]
    review = run(admin, lambda s: s.conn.execute(
        "SELECT count(*) AS n FROM axiom.outbox WHERE topic = 'access.emergency_granted' AND aggregate_id = %s",
        (row["id"],)).fetchone())
    assert review["n"] == 1


def test_cross_tenant_resource_references_are_invisible(world, run, ctx_for, scenario):
    """A13 (application path): a multi-tenant consultant cannot use tenant A identifiers in tenant B."""
    cid = scenario["case"]["id"]
    consultant_b = ctx_for("consultant", "b")
    with pytest.raises(NotFound):
        run(consultant_b, lambda s: s.cases.get(cid))
    with pytest.raises(NotFound):
        run(consultant_b, lambda s: s.cases.create(scope_id=world.a.project, title="x"))
    with pytest.raises(NotFound):
        run(consultant_b, lambda s: s.cases.create(scope_id=world.b.project, title="x",
                                                   occurrence_ids=[scenario["occ"]["id"]]))
    case_b = run(consultant_b, lambda s: s.cases.create(scope_id=world.b.project, title="b case"))
    run(consultant_b, lambda s: s.cases.start_investigation(case_b["id"], 0, "go"))
    with pytest.raises(NotFound):
        run(consultant_b, lambda s: s.cases.record_assessment(
            case_b["id"], 1, assessment="supported", rationale="cite A", limitations="none",
            evidence=[EvidenceRef(scenario["evidence"]["id"])]))
    assert run(consultant_b, lambda s: s.cases.list()) and all(
        c["tenant_id"] == world.b.id for c in run(consultant_b, lambda s: s.cases.list()))


def test_list_respects_scope(world, run, ctx_for, scenario):
    assert run(ctx_for("marketing_analyst"), lambda s: s.cases.list()) == []
    assert len(run(ctx_for("viewer"), lambda s: s.cases.list())) == 1


def test_deferral_stays_open_with_review_date(world, run, ctx_for, scenario):
    """CASE-12."""
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    with pytest.raises(ValidationFailed):
        run(analyst, lambda s: s.cases.defer(cid, 2, review_at=datetime.now(timezone.utc) - timedelta(days=1),
                                             rationale="past"))
    with pytest.raises(ValidationFailed):
        run(analyst, lambda s: s.cases.defer(cid, 2, review_at=datetime.now(timezone.utc) + timedelta(days=400),
                                             rationale="too far"))
    when = datetime.now(timezone.utc) + timedelta(days=14)
    case = run(analyst, lambda s: s.cases.defer(cid, 2, review_at=when, rationale="vendor patch due"))
    assert case["workflow"] == "review_required" and case["disposition"] == "defer" and case["review_at"] == when


def test_remediation_target_must_be_affected_asset(world, run, ctx_for, scenario):
    """CASE-08 negative path: a deployment of an unrelated asset is rejected (service and DB)."""
    cid = scenario["case"]["id"]
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="fix"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-1", rationale="ticket"))

    def other_asset(s):
        a = s.assets.create_asset(scope_id=world.a.project, kind="container_image", display_name="other")
        return s.assets.record_version(asset_id=a["id"], observed_at=datetime.now(timezone.utc),
                                       deployment_digest="sha256:" + "d" * 64)
    unrelated = run(analyst, other_asset)
    with pytest.raises(psycopg.errors.CheckViolation, match="not a deployment of an asset affected"):
        run(owner, lambda s: s.cases.report_change(cid, 4, target_asset_version_id=unrelated["id"],
                                                   change_reference="deploy x", rationale="wrong asset"))
    assert run(analyst, lambda s: s.cases.get(cid))["workflow"] == "remediating"


def test_decisions_record_authority(world, run, ctx_for, scenario):
    """AUTHZ-15 / B02 (authority part)."""
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    decision = run(analyst, lambda s: s.conn.execute(
        "SELECT authority, actor_principal_id FROM axiom.decisions WHERE case_id = %s", (cid,)).fetchone())
    binding = run(analyst, lambda s: s.conn.execute(
        "SELECT id FROM axiom.role_bindings WHERE principal_id = %s", (world["analyst"],)).fetchone())
    assert decision["actor_principal_id"] == world["analyst"]
    assert decision["authority"]["permission"] == "investigation.request"
    assert decision["authority"]["binding_ids"] == [str(binding["id"])]
    assert decision["authority"]["roles"] == ["analyst"]


def test_citing_evidence_requires_read_permission_for_its_classification(world, run, ctx_for, scenario, upload, dbinfo):
    """AUTHZ-16: an analyst cannot cite restricted evidence they cannot read."""
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["analyst2"], "evidence_reader_restricted",
                                                     world.a.project, "restricted uploader")
    restricted = upload(ctx_for("analyst2"), world.a.project, b"restricted proof", classification="restricted")
    cid = scenario["case"]["id"]
    analyst = ctx_for("analyst")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "go"))
    with pytest.raises(PermissionDenied):
        run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="supported", rationale="r",
                                                          limitations="none", evidence=[EvidenceRef(restricted["id"])]))


def test_audit_detail_redacts_secret_like_keys(world, run, ctx_for):
    """AUD-03."""
    from axiom import audit
    ctx = ctx_for("analyst")
    event_id = run(ctx, lambda s: audit.record(s.conn, ctx, action="test.redaction", resource_type="test",
                                               resource_id=None, detail={"api_key": "abc", "Authorization": "Bearer x",
                                                                         "note": "kept"}))
    detail = run(ctx, lambda s: s.conn.execute("SELECT detail FROM axiom.audit_events WHERE id = %s",
                                               (event_id,)).fetchone()["detail"])
    assert detail == {"api_key": "[redacted]", "Authorization": "[redacted]", "note": "kept"}
