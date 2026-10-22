"""Verification worker (ADR 0014) against a controlled local TLS check endpoint (fixture, not a real integration).

Covers: the distinct identity and its permissions, authority evaluated at execution, provenance, the explicit
outcome rules end to end, retries, crashes, lost leases, stale case versions, revocation before, during and at
commit, tenant and project boundaries, and the reopen and closure restrictions.
"""
from __future__ import annotations

import hashlib
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.access import PermissionDenied
from axiom.db import TenantContext
from axiom.ingestion.sync import SyncService
from axiom.jobs import Worker, WorkerConfig
from axiom.provisioning import Provisioner
from axiom.secretrefs import SecretRefResolver
from axiom.verification import checks
from axiom.verification import worker as vworker
from axiom.verification.routing import KIND
from axiom.verification.worker import VerificationCheckHandler

from . import check_target
from .test_cases import DIGEST_NEW, DIGEST_OLD, advance_to_verification, scenario  # noqa: F401

pytestmark = pytest.mark.db
TOKEN = "check-endpoint-test-token-7f3a"      # local test credential, mounted as a file in a temp directory


def now_iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def clean(request, **over):
    doc = {"schema": checks.SCHEMA, "request_id": request["request_id"], "observed_at": now_iso(),
           "deployment_digest": request["deployment_digest"], "coverage": "complete",
           "results": [{"criterion": "original_condition", "result": "absent"}]}
    return 200, {**doc, **over}


@pytest.fixture()
def target(tmp_path):
    t = check_target.start(tmp_path)
    t.behaviour = clean
    yield t
    t.stop()


@pytest.fixture()
def setup(db, world, dbinfo, ctx_for, target, tmp_path, evidence):
    """Verification identity bound at the tenant root, a check connection on the project, and a worker."""
    prov = Provisioner(dbinfo.admin_cli_dsn)
    verifier = prov.create_verification_identity(world.a.id)
    prov.bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "configure check endpoint")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "check-token").write_text(TOKEN + "\n")
    connection = SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="verification_check", scope_id=world.a.project, display_name="local check fixture",
        base_url=target.base_url, credential_ref=f"secretref:file{secrets_dir}/check-token", config={})

    def factory(conn, secrets, clock):
        ref = conn["credential_ref"]
        return checks.CheckEndpointClient(conn["base_url"], lambda: secrets.resolve(ref), verify=ssl.create_default_context(cafile=str(target.ca_path)),
                                          clock=clock, timeout=3)
    handler = VerificationCheckHandler(evidence, secrets=SecretRefResolver(env="test", file_dirs=(str(secrets_dir),)),
                                       client_factory=factory)

    class S:
        pass
    s = S()
    s.verifier, s.connection, s.handler, s.prov = verifier, connection, handler, prov
    s.worker = Worker(db, [handler], config=WorkerConfig(lease_seconds=30))
    s.vctx = lambda: TenantContext(world.a.id, verifier, "workload", "test-verifier")
    return s


def job_for(admin_conn, case_id):
    return admin_conn.execute("SELECT * FROM axiom.jobs WHERE kind = %s AND aggregate_id = %s", (KIND, case_id)).fetchone()


def runs(admin_conn, case_id):
    return admin_conn.execute("""SELECT r.*, o.rule, o.source_origin, o.requested_at, o.received_at, o.http_status,
                                        o.response_digest, o.target_observed_at, o.job_id, o.attempts, o.worker
                                   FROM axiom.verification_runs r
                                   LEFT JOIN axiom.verification_observations o ON o.verification_run_id = r.id
                                  WHERE r.case_id = %s ORDER BY r.recorded_at""", (case_id,)).fetchall()


def make_due(admin_conn, job_id):
    admin_conn.execute("UPDATE axiom.jobs SET due_at = clock_timestamp(), record_version = record_version + 1 "
                       "WHERE id = %s", (job_id,))


# ------------------------------------------------------------------------------------------------ happy paths
def test_a_passed_check_is_recorded_by_the_verification_identity_with_provenance(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    case = advance_to_verification(run, ctx_for, world, scenario)
    cid = case["id"]
    job = job_for(admin_conn, cid)
    assert job["payload"] == {"case_id": str(cid), "remediation_report_id": job["payload"]["remediation_report_id"]}
    assert job["created_by"] == world["owner"] and job["dedupe_key"].startswith("verification:")
    setup.worker.run_once(only_tenants={world.a.id})
    j0 = job_for(admin_conn, cid); assert j0["state"] == "succeeded", (j0["state"], j0["last_error"], j0["attempts"])
    [req] = target.requests
    assert req["path"] == "/v1/checks" and req["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert req["json"]["deployment_digest"] == DIGEST_NEW and req["json"]["request_id"] == str(job["id"])
    assert req["json"]["criteria"][0]["conditions"] == [
        {"vulnerability_ref": "CVE-2099-0001", "component": "openssl@3.0.1"}]
    [r] = runs(admin_conn, cid)
    assert r["outcome"] == "passed" and r["coverage"] == "complete" and r["recorded_by"] == setup.verifier
    assert r["rule"] == "condition_absent" and r["source_origin"] == target.base_url and r["http_status"] == 200
    assert r["requested_at"] <= r["received_at"] and r["target_observed_at"] is not None
    assert r["job_id"] == job["id"] and r["attempts"] == 1
    ev = admin_conn.execute("SELECT * FROM axiom.evidence_objects WHERE id = %s", (r["evidence_object_id"],)).fetchone()
    assert ev["status"] == "verified" and ev["classification"] == "confidential"
    assert ev["created_by"] == setup.verifier and ev["observed_digest"] == r["response_digest"]
    d = admin_conn.execute("SELECT * FROM axiom.decisions WHERE id = %s", (r["decision_id"],)).fetchone()
    assert d["kind"] == "verification_review" and d["actor_principal_id"] == setup.verifier
    assert d["authority"]["permission"] == "verification.record" and d["authority"]["roles"] == ["verification_worker"]
    a = admin_conn.execute("""SELECT actor_kind FROM axiom.audit_events WHERE actor_principal_id = %s
                               AND action = 'case.verification_passed'""", (setup.verifier,)).fetchone()
    assert a["actor_kind"] == "workload"
    assert job_for(admin_conn, cid)["state"] == "succeeded"
    assert TOKEN not in str(job_for(admin_conn, cid)["result"])

    # the worker's pass does not close the case; closing is a person's decision with closure.propose
    with pytest.raises(PermissionDenied):
        run(setup.vctx(), lambda s: s.cases.close_verified(cid, 6, verification_run_id=r["id"], rationale="auto"))
    closed = run(ctx_for("analyst2"), lambda s: s.cases.close_verified(cid, 6, verification_run_id=r["id"],
                                                                      rationale="automated check passed"))
    assert closed["workflow"] == "closed"
    hist = run(ctx_for("analyst"), lambda s: s.cases.history(cid))["verifications"]
    assert hist[0]["recorder_kind"] == "workload" and hist[0]["observation"]["rule"] == "condition_absent"


def test_a_present_condition_fails_verification_and_returns_the_case_to_remediation(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    target.behaviour = lambda req: clean(req, results=[{"criterion": "original_condition", "result": "present"}])
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"]) == ("failed", "condition_present")
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "remediating"


INCONCLUSIVE = {
    "observation_stale": lambda req: clean(req, observed_at=now_iso(-timedelta(hours=2))),
    "observation_predates_change": lambda req: clean(req, observed_at=now_iso(-timedelta(minutes=10))),
    "observation_time_in_future": lambda req: clean(req, observed_at=now_iso(timedelta(hours=1))),
    "observation_time_unknown": lambda req: clean(req, observed_at="yesterday"),
    "different_deployment": lambda req: clean(req, deployment_digest=DIGEST_OLD),
    "deployment_unknown": lambda req: clean(req, deployment_digest=None),
    "contradictory_results": lambda req: clean(req, results=[{"criterion": "original_condition", "result": "absent"},
                                                             {"criterion": "original_condition", "result": "present"}]),
    "incomplete_coverage": lambda req: clean(req, coverage="partial"),
    "malformed_response": lambda req: (200, b"<html>not json</html>"),
    "target_refused": lambda req: (403, {"error": "forbidden"}),
}


@pytest.mark.parametrize("rule", sorted(INCONCLUSIVE))
def test_missing_stale_contradictory_or_refused_evidence_is_inconclusive(
        world, run, ctx_for, scenario, setup, target, admin_conn, rule):  # noqa: F811
    target.behaviour = INCONCLUSIVE[rule]      # observation_predates_change: the change was reported moments ago
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"]) == ("inconclusive", rule)
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "review_required"


def test_a_case_without_a_checkable_condition_is_inconclusive_without_calling_the_endpoint(
        world, run, ctx_for, setup, target, admin_conn, upload):
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    now = datetime.now(timezone.utc)

    def build(s):
        asset = s.assets.create_asset(scope_id=world.a.project, kind="container_image", display_name="billing")
        old = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_OLD)
        new = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_NEW)
        occ = s.assets.record_occurrence(source_system="manual", source_finding_id="m-1", asset_version_id=old["id"],
                                         component_locator="config", vulnerability_ref=None)
        return s.cases.create(scope_id=world.a.project, title="weak config", occurrence_ids=[occ["id"]]), new
    case, new = run(analyst, build)
    from .test_cases import advance_to_review
    ev = upload(analyst, world.a.project, b"config review")
    cid = case["id"]
    advance_to_review(run, analyst, cid, ev["id"])
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="fix"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-2", rationale="ticket"))
    run(owner, lambda s: s.cases.report_change(cid, 4, target_asset_version_id=new["id"], change_reference="d",
                                               rationale="done"))
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"], r["http_status"]) == ("inconclusive", "no_checkable_condition", None)
    assert target.requests == []


def test_redirects_are_not_followed(world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    target.behaviour = lambda req: (302, None)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"], r["http_status"]) == ("inconclusive", "target_refused", 302)
    assert len(target.requests) == 1


# --------------------------------------------------------------------------------------- unavailable / retries
def test_an_unavailable_endpoint_is_retried_then_recorded_inconclusive(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    target.behaviour = lambda req: (503, None)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    job = job_for(admin_conn, cid)
    for attempt in range(1, job["max_attempts"]):
        setup.worker.run_once(only_tenants={world.a.id})
        j = job_for(admin_conn, cid)
        assert j["state"] == "queued" and "HTTP 503" in j["last_error"] and j["attempts"] == attempt
        assert runs(admin_conn, cid) == []
        make_due(admin_conn, job["id"])
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"], r["attempts"]) == ("inconclusive", "target_unavailable", job["max_attempts"])
    assert r["response_digest"] is None and r["evidence_object_id"] is None
    assert len(target.requests) == job["max_attempts"]


def test_a_stopped_endpoint_is_unavailable_not_passed(world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    target.stop()
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "queued" and "unreachable" in j["last_error"] and runs(admin_conn, cid) == []


def test_a_slow_endpoint_times_out_and_is_retried(world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    def slow(req):
        time.sleep(4)                       # the test client's timeout is 3 s
        return clean(req)
    target.behaviour = slow
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "queued" and j["last_error"] == "check endpoint timed out" and runs(admin_conn, cid) == []
    assert TOKEN not in j["last_error"]


# --------------------------------------------------------------------------------------- duplicates and crashes
def test_a_crash_after_commit_does_not_record_twice(world, run, ctx_for, scenario, setup, target, admin_conn,
                                                    monkeypatch):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    job = job_for(admin_conn, cid)

    def crash(*_a, **_k):           # phase C committed; the process dies before the job is marked finished
        raise SystemExit("worker killed")
    with monkeypatch.context() as m:
        m.setattr(setup.worker, "_finish", crash)
        with pytest.raises(SystemExit):
            setup.worker.run_once(only_tenants={world.a.id})
    assert job_for(admin_conn, cid)["state"] == "running" and len(runs(admin_conn, cid)) == 1
    admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 s',
                          record_version = record_version + 1 WHERE id = %s""", (job["id"],))
    setup.worker.run_once(only_tenants={world.a.id})      # another pass reclaims the job after the lease expired
    j = job_for(admin_conn, cid)
    assert j["state"] == "succeeded" and j["result"]["status"] == "already_recorded" and j["claims"] == 2
    assert len(runs(admin_conn, cid)) == 1 and len(target.requests) == 1


def test_a_worker_that_lost_its_lease_while_checking_records_nothing(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    job = job_for(admin_conn, cid)

    def steal(req):              # another worker claims the job while this one is waiting for the endpoint
        admin_conn.execute("UPDATE axiom.jobs SET lease_token = lease_token + 1, record_version = record_version + 1 "
                           "WHERE id = %s", (job["id"],))
        return clean(req)
    target.behaviour = steal
    setup.worker.run_once(only_tenants={world.a.id})
    assert runs(admin_conn, cid) == []
    events = [e["event"] for e in admin_conn.execute(
        "SELECT event FROM axiom.job_events WHERE job_id = %s ORDER BY created_at", (job["id"],))]
    assert "stale_result_discarded" in events


def test_a_case_changed_during_the_check_is_not_silently_overwritten(
        world, run, ctx_for, scenario, setup, target, admin_conn, upload):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    check = upload(ctx_for("analyst2"), world.a.project, b"manual rescan: clean")

    def human_verifies_meanwhile(req):
        run(ctx_for("analyst2"), lambda s: s.cases.record_verification(
            cid, 5, claimed_result="passed", coverage="complete", criteria={"check": "manual"},
            observed_deployment_digest=DIGEST_NEW, evidence_id=check["id"], rationale="manual rescan"))
        return clean(req)
    target.behaviour = human_verifies_meanwhile
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "queued" and "case changed" in j["last_error"]
    make_due(admin_conn, j["id"])
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "succeeded" and j["result"] == {"status": "skipped", "reason": "already_verified"}
    [r] = runs(admin_conn, cid)
    assert r["recorded_by"] == world["analyst2"] and r["rule"] is None      # only the person's result exists


def test_one_job_per_reported_change(world, run, ctx_for, scenario, setup, admin_conn):  # noqa: F811
    from axiom.jobs import enqueue
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    job = job_for(admin_conn, cid)
    again = run(ctx_for("owner"), lambda s: enqueue(s.conn, s.authz.ctx, kind=KIND, version=1,
                                                    dedupe_key=job["dedupe_key"], payload=job["payload"]))
    assert again["id"] == job["id"]


# --------------------------------------------------------------------------------------- authority
def _verifier_binding(admin_conn, verifier):
    return admin_conn.execute("SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL",
                              (verifier,)).fetchone()["id"]


def test_authority_is_evaluated_when_the_job_runs_not_when_it_was_queued(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    binding = _verifier_binding(admin_conn, setup.verifier)
    run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=binding, reason="worker retired"))
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "failed" and j["last_error"].startswith("authority_missing")
    assert runs(admin_conn, cid) == [] and target.requests == []


def test_revocation_while_the_check_is_running_prevents_recording(
        world, run, ctx_for, scenario, setup, target, admin_conn):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    binding = _verifier_binding(admin_conn, setup.verifier)

    def revoke_then_answer(req):
        run(ctx_for("admin"), lambda s: s.tenancy.suspend_membership(principal_id=setup.verifier, reason="incident"))
        return clean(req)
    target.behaviour = revoke_then_answer
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "failed" and j["last_error"].startswith("authority_revoked")
    assert runs(admin_conn, cid) == []
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "awaiting_verification"
    _ = binding


def test_a_revocation_racing_the_commit_waits_for_it(world, run, ctx_for, scenario, setup, target, admin_conn,
                                                     monkeypatch):  # noqa: F811
    """Phase C holds the verifier's binding share-locked from its permission check until commit; a revocation
    issued after that check completes only after the verification is committed."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    binding = _verifier_binding(admin_conn, setup.verifier)
    finished = {}

    class Racing(vworker.CaseService):
        def record_verification(self, *a, **kw):
            out = super().record_verification(*a, **kw)

            def revoke():
                run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=binding, reason="race"))
                finished["at"] = time.monotonic()
            t = threading.Thread(target=revoke)
            t.start()
            t.join(1.5)
            finished["blocked"] = "at" not in finished
            finished["thread"] = t
            return out
    monkeypatch.setattr(vworker, "CaseService", Racing)
    setup.worker.run_once(only_tenants={world.a.id})
    committed_at = time.monotonic()
    finished["thread"].join(10)
    assert finished["blocked"] and finished["at"] <= committed_at + 10
    [r] = runs(admin_conn, cid)
    assert r["outcome"] == "passed"
    rb = admin_conn.execute("SELECT revoked_at FROM axiom.role_bindings WHERE id = %s", (binding,)).fetchone()
    assert rb["revoked_at"] > r["recorded_at"]


def test_project_boundary_binding_elsewhere_gives_no_authority(world, run, ctx_for, scenario, dbinfo, target,
                                                               evidence, db, admin_conn):  # noqa: F811
    prov = Provisioner(dbinfo.admin_cli_dsn)
    verifier = prov.create_verification_identity(world.a.id, world.a.other_project)     # marketing only
    prov.bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "configure")
    SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="verification_check", scope_id=world.a.root, display_name="root check",
        base_url=target.base_url, credential_ref=None, config={})
    handler = VerificationCheckHandler(evidence, client_factory=lambda c, s, clock: checks.CheckEndpointClient(
        c["base_url"], verify=ssl.create_default_context(cafile=str(target.ca_path)), clock=clock))
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    Worker(db, [handler]).run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "failed" and "authority_missing" in j["last_error"] and target.requests == []
    _ = verifier


def test_no_job_without_a_covering_check_endpoint(world, run, ctx_for, scenario, dbinfo, db, admin_conn,
                                                   target):  # noqa: F811
    """A check endpoint configured for another project does not cover this case's project."""
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "cfg")
    SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="verification_check", scope_id=world.a.other_project, display_name="marketing",
        base_url=target.base_url, credential_ref=None, config={})
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    assert job_for(admin_conn, cid) is None


def test_no_verification_identity_needs_an_operator(world, run, ctx_for, scenario, dbinfo, db, target, evidence,
                                                    admin_conn):  # noqa: F811
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "cfg")
    SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="verification_check", scope_id=world.a.project, display_name="check",
        base_url=target.base_url, credential_ref=None, config={})
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    Worker(db, [VerificationCheckHandler(evidence)]).run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "needs_operator" and "verification identity" in j["operator_reason"]
    assert target.requests == []


# --------------------------------------------------------------------------------------- what the identity cannot do
def test_the_verification_identity_holds_only_its_workload_permissions(world, dbinfo, admin_conn, setup):
    perms = {r["permission"] for r in admin_conn.execute(
        "SELECT permission FROM axiom.role_permissions WHERE role_id = 'verification_worker'")}
    assert perms == {"verification.record", "evidence.upload", "evidence.read:confidential"}
    assert admin_conn.execute("SELECT principal_kind FROM axiom.roles WHERE id = 'verification_worker'"
                              ).fetchone()["principal_kind"] == "workload"
    with pytest.raises(psycopg.errors.InsufficientPrivilege):     # never on a person
        setup.prov.bootstrap_role(world.a.id, world["analyst"], "verification_worker", world.a.project, "x")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):     # and the identity gets no discretionary role
        setup.prov.bootstrap_role(world.a.id, setup.verifier, "analyst", world.a.project, "x")
    assert setup.verifier != world.a.system
    with pytest.raises(RuntimeError, match="already has"):
        setup.prov.create_verification_identity(world.a.id)


def test_the_verification_identity_cannot_reopen_close_or_decide(world, run, ctx_for, scenario, setup, db,
                                                                  admin_conn):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    v = setup.vctx()
    with pytest.raises(PermissionDenied):
        run(v, lambda s: s.cases.create(scope_id=world.a.project, title="by the verifier"))
    for kind, outcome in [("reopen", "recurrence"), ("assessment", "supported"), ("closure", "verified_remediated")]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with db.tenant_tx(v) as conn:
                conn.execute("""INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale,
                                    actor_principal_id, authority) VALUES (%s, gen_random_uuid(), %s, %s, %s, 'x', %s,
                                    '{"permission": "case.reopen"}')""", (v.tenant_id, cid, kind, outcome, v.principal_id))


def test_observations_cannot_be_forged_or_changed(world, run, ctx_for, scenario, setup, target, db, admin_conn,
                                                  upload):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    row = admin_conn.execute("SELECT * FROM axiom.verification_observations WHERE verification_run_id = %s",
                             (r["id"],)).fetchone()
    cols = [c for c in row.keys() if c not in ("id", "recorded_at")]
    insert = (f"INSERT INTO axiom.verification_observations(id, {', '.join(cols)}) "
              f"VALUES (gen_random_uuid(), {', '.join(['%s'] * len(cols))})")
    analyst = ctx_for("analyst")
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="principal bound"):      # someone else's name
        with db.tenant_tx(analyst) as conn:
            conn.execute(insert, [row[c] for c in cols])
    with pytest.raises(psycopg.errors.CheckViolation, match="same transaction"):            # an older run
        with db.tenant_tx(setup.vctx()) as conn:
            conn.execute(insert, [row[c] if c != "job_id" else row["job_id"] for c in cols])
    for stmt in ("UPDATE axiom.verification_observations SET rule = 'condition_absent' WHERE id = %s",
                 "DELETE FROM axiom.verification_observations WHERE id = %s"):
        with pytest.raises(psycopg.Error):
            with db.tenant_tx(setup.vctx()) as conn:
                conn.execute(stmt, (row["id"],))
    assert hashlib.sha256(b"").hexdigest() != row["response_digest"]


def test_the_provisioning_cli_creates_the_identity(dbinfo, world, admin_conn, capsys):
    import json as _json
    from axiom import provisioning
    assert provisioning.main(["--dsn", dbinfo.admin_cli_dsn, "create-verification-identity",
                              "--tenant", str(world.b.id), "--scope", str(world.b.project)]) == 0
    pid = _json.loads(capsys.readouterr().out)["principal_id"]
    row = admin_conn.execute("""SELECT t.verification_principal_id, p.kind, rb.role_id, rb.scope_id
                                  FROM axiom.tenants t JOIN axiom.principals p ON p.id = t.verification_principal_id
                                  JOIN axiom.role_bindings rb ON rb.principal_id = p.id WHERE t.id = %s""",
                             (world.b.id,)).fetchone()
    assert (str(row["verification_principal_id"]), row["kind"], row["role_id"], row["scope_id"]) == (
        pid, "workload", "verification_worker", world.b.project)
