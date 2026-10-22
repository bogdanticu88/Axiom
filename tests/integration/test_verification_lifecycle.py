"""Verification worker lifecycle and evidence integrity (ADR 0014).

Each test checks the records that matter (verification runs, decisions, observations, evidence and audit), not only
the job's status. The check endpoint is the local TLS fixture.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import psycopg
import pytest

from axiom.access import Authorizer
from axiom.db import TenantContext
from axiom.domains.cases.service import CaseService
from axiom.errors import NotFound
from axiom.jobs import Worker, WorkerConfig
from axiom.verification import worker as vworker
from axiom.verification.routing import KIND

from .test_cases import DIGEST_NEW, advance_to_verification, scenario  # noqa: F401
from .test_verification_worker import clean, job_for, make_due, runs, setup, target  # noqa: F401

pytestmark = pytest.mark.db
DIGEST_LATER = "sha256:" + "d" * 64


def records(admin_conn, cid, verifier):
    one = lambda sql, *a: admin_conn.execute(sql, a).fetchone()["n"]      # noqa: E731
    return {
        "runs": one("SELECT count(*) AS n FROM axiom.verification_runs WHERE case_id = %s", cid),
        "decisions": one("SELECT count(*) AS n FROM axiom.decisions WHERE case_id = %s AND kind = 'verification_review'",
                         cid),
        "observations": one("SELECT count(*) AS n FROM axiom.verification_observations WHERE case_id = %s", cid),
        "verifier_evidence": one("SELECT count(*) AS n FROM axiom.evidence_objects WHERE created_by = %s", verifier),
        "audit": one("""SELECT count(*) AS n FROM axiom.audit_events WHERE resource_id = %s
                         AND action LIKE 'case.verification_%%'""", str(cid)),
    }


def test_concurrent_workers_execute_a_job_once(world, run, ctx_for, scenario, setup, target, admin_conn, db):  # noqa: F811
    """Two workers race for the job while the endpoint is slow; only the lease holder calls it and records."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    gate = threading.Event()

    def slow(req):
        gate.wait(5)
        return clean(req)
    target.behaviour = slow
    other = Worker(db, [setup.handler], worker_id="second", config=WorkerConfig(lease_seconds=30))
    t = threading.Thread(target=lambda: setup.worker.run_once(only_tenants={world.a.id}))
    t.start()
    for _ in range(50):                                  # wait until the first worker holds the lease
        if job_for(admin_conn, cid)["state"] == "running":
            break
        threading.Event().wait(0.1)
    assert other.run_once(only_tenants={world.a.id}) == 0
    gate.set()
    t.join(20)
    assert len(target.requests) == 1
    assert records(admin_conn, cid, setup.verifier) == {"runs": 1, "decisions": 1, "observations": 1,
                                                        "verifier_evidence": 1, "audit": 1}


def test_a_crash_after_the_response_and_before_the_commit(world, run, ctx_for, scenario, setup, target, admin_conn,  # noqa: F811
                                                          monkeypatch):
    """The response is stored as evidence, then the process dies before the commit. Nothing about the case is
    recorded; the reclaimed job asks the endpoint again and records once. The first attempt's evidence stays,
    attributed to the worker and cited by nothing."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]

    class Dies(vworker.CaseService):
        def record_verification(self, *a, **kw):
            raise SystemExit("killed before commit")
    with monkeypatch.context() as m:
        m.setattr(vworker, "CaseService", Dies)
        with pytest.raises(SystemExit):
            setup.worker.run_once(only_tenants={world.a.id})
    assert records(admin_conn, cid, setup.verifier) == {"runs": 0, "decisions": 0, "observations": 0,
                                                        "verifier_evidence": 1, "audit": 0}
    job = job_for(admin_conn, cid)
    admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 s',
                          record_version = record_version + 1 WHERE id = %s""", (job["id"],))
    setup.worker.run_once(only_tenants={world.a.id})
    assert len(target.requests) == 2
    assert records(admin_conn, cid, setup.verifier) == {"runs": 1, "decisions": 1, "observations": 1,
                                                        "verifier_evidence": 2, "audit": 1}
    cited = admin_conn.execute("SELECT evidence_object_id FROM axiom.verification_runs WHERE case_id = %s",
                               (cid,)).fetchone()["evidence_object_id"]
    orphans = admin_conn.execute("""SELECT count(*) AS n FROM axiom.evidence_objects
                                     WHERE created_by = %s AND id <> %s""", (setup.verifier, cited)).fetchone()["n"]
    assert orphans == 1


def test_a_crash_after_the_commit_and_before_the_acknowledgement(world, run, ctx_for, scenario, setup, target,  # noqa: F811
                                                                 admin_conn, monkeypatch):
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    with monkeypatch.context() as m:
        m.setattr(setup.worker, "_finish", lambda *a, **k: (_ for _ in ()).throw(SystemExit("killed")))
        with pytest.raises(SystemExit):
            setup.worker.run_once(only_tenants={world.a.id})
    job = job_for(admin_conn, cid)
    admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 s',
                          record_version = record_version + 1 WHERE id = %s""", (job["id"],))
    setup.worker.run_once(only_tenants={world.a.id})
    assert job_for(admin_conn, cid)["result"]["status"] == "already_recorded" and len(target.requests) == 1
    assert records(admin_conn, cid, setup.verifier) == {"runs": 1, "decisions": 1, "observations": 1,
                                                        "verifier_evidence": 1, "audit": 1}


def test_a_second_job_for_an_already_verified_report_is_skipped(world, run, ctx_for, scenario, setup, target,  # noqa: F811
                                                                 admin_conn):
    """Isolates the second idempotency layer: a different job (so the job-level check cannot apply) for a report that
    already has a verification is skipped before the endpoint is called."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    first = job_for(admin_conn, cid)
    setup.worker.run_once(only_tenants={world.a.id})
    from axiom.jobs import enqueue
    run(ctx_for("owner"), lambda s: enqueue(s.conn, s.authz.ctx, kind=KIND, version=1, dedupe_key="duplicate-delivery",
                                            payload=first["payload"], aggregate=("finding_case", cid)))
    setup.worker.run_once(only_tenants={world.a.id})
    dup = admin_conn.execute("SELECT * FROM axiom.jobs WHERE dedupe_key = 'duplicate-delivery'").fetchone()
    assert dup["result"] == {"status": "skipped", "reason": "already_verified"} and len(target.requests) == 1
    assert records(admin_conn, cid, setup.verifier)["observations"] == 1


def test_the_database_refuses_a_second_observation_for_a_job(world, run, ctx_for, scenario, setup, target,  # noqa: F811
                                                             admin_conn):
    """The last layer: even if both application checks were bypassed, one job cannot leave two observations."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    row = admin_conn.execute("SELECT * FROM axiom.verification_observations WHERE case_id = %s", (cid,)).fetchone()
    cols = [c for c in row.keys() if c not in ("id", "recorded_at")]
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin_conn.execute("SET session_replication_role = replica")      # skip the guard trigger: isolate the key
        try:
            admin_conn.execute(f"INSERT INTO axiom.verification_observations(id, {', '.join(cols)}) "
                               f"VALUES (gen_random_uuid(), {', '.join(['%s'] * len(cols))})", [row[c] for c in cols])
        finally:
            admin_conn.execute("SET session_replication_role = origin")


def test_a_retry_after_revocation_fails_without_calling_the_endpoint_again(world, run, ctx_for, scenario, setup,  # noqa: F811
                                                                           target, admin_conn):
    target.behaviour = lambda req: (503, None)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})
    job = job_for(admin_conn, cid)
    assert job["state"] == "queued" and len(target.requests) == 1
    binding = admin_conn.execute("SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL",
                                 (setup.verifier,)).fetchone()["id"]
    run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=binding, reason="worker retired"))
    make_due(admin_conn, job["id"])
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "failed" and j["last_error"].startswith("authority_missing") and len(target.requests) == 1
    assert records(admin_conn, cid, setup.verifier) == {"runs": 0, "decisions": 0, "observations": 0,
                                                        "verifier_evidence": 0, "audit": 0}


def test_a_case_sent_back_to_review_while_checking_is_left_alone(world, run, ctx_for, scenario, setup, target,  # noqa: F811
                                                                 admin_conn, upload):
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]

    def person_records_inconclusive(req):
        run(ctx_for("analyst2"), lambda s: s.cases.record_verification(
            cid, 5, claimed_result="inconclusive", coverage="partial", criteria={"check": "manual"},
            observed_deployment_digest=DIGEST_NEW, rationale="could not reach the host"))
        return clean(req)
    target.behaviour = person_records_inconclusive
    setup.worker.run_once(only_tenants={world.a.id})
    make_due(admin_conn, job_for(admin_conn, cid)["id"])
    setup.worker.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["result"] == {"status": "skipped", "reason": "case_not_awaiting_verification"}
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "review_required"
    rec = records(admin_conn, cid, setup.verifier)
    assert (rec["runs"], rec["observations"]) == (1, 0)                # only the person's result


def test_a_newer_deployment_seen_during_the_check_does_not_verify_the_reported_one(  # noqa: F811
        world, run, ctx_for, scenario, setup, target, admin_conn):
    """While the check runs, a newer deployment of the asset is recorded and the endpoint examines that one."""
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]

    def redeployed(req):
        run(ctx_for("analyst"), lambda s: s.assets.record_version(
            asset_id=scenario["asset"]["id"], observed_at=datetime.now(timezone.utc), deployment_digest=DIGEST_LATER))
        return clean(req, deployment_digest=DIGEST_LATER)
    target.behaviour = redeployed
    setup.worker.run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"]) == ("inconclusive", "different_deployment")
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "review_required"


def test_another_tenants_evidence_cannot_be_cited(world, run, ctx_for, scenario, setup, admin_conn, upload):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    foreign = upload(ctx_for("analyst_b", tenant="b"), world.b.project, b"tenant b rescan", classification="confidential")
    v = TenantContext(world.a.id, setup.verifier, "workload", "t")
    with pytest.raises(NotFound):
        with setup.worker.db.tenant_tx(v) as conn:
            CaseService(conn, v, Authorizer(conn, v)).record_verification(
                cid, 5, claimed_result="passed", coverage="complete", criteria={"check": "x"},
                observed_deployment_digest=DIGEST_NEW, evidence_id=foreign["id"], rationale="borrowed evidence")
    assert runs(admin_conn, cid) == []
