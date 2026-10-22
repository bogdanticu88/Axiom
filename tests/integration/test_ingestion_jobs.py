"""Ingestion runs and scheduled sweeps on the job runner (ADR 0006)."""
from __future__ import annotations

from pathlib import Path

import pytest

from axiom.domains.cases.jobs import KIND as RISK_SWEEP
from axiom.domains.evidence.service import EvidenceService
from axiom.ingestion.jobs import KIND as RUN_KIND
from axiom.ingestion.pipeline import IngestionService
from axiom.ingestion.sync import SyncService
from axiom.jobs import WorkerConfig
from axiom.workers.jobs import build_worker

pytestmark = pytest.mark.db
TRIVY = Path(__file__).resolve().parent.parent / "fixtures/trivy/debian-bullseye-20230612-slim.subset.json"


@pytest.fixture()
def stack(db, object_store):
    ingestion = IngestionService(db, object_store, page_size=7, lease_seconds=60)
    sync = SyncService(db, ingestion, EvidenceService(db, object_store, max_bytes=10**7))
    return ingestion, sync


def jobs_for(run, ctx, kind, **where):
    cond = " AND ".join(f"{k} = %({k})s" for k in where) or "true"
    return run(ctx, lambda s: s.conn.execute(f"SELECT * FROM axiom.jobs WHERE kind = %(kind)s AND {cond} "
                                             "ORDER BY created_at", {"kind": kind, **where}).fetchall())


def request(world, ctx_for, upload, ingestion):
    analyst = ctx_for("analyst")
    ev = upload(analyst, world.a.project, TRIVY.read_bytes(), classification="internal")
    return ingestion.request_import(analyst, evidence_id=ev["id"], adapter="trivy_json", scope_id=world.a.project)


def test_import_request_enqueues_exactly_one_job_in_the_same_transaction(world, run, ctx_for, upload, stack):
    ingestion, sync = stack
    r = request(world, ctx_for, upload, ingestion)
    [job] = jobs_for(run, ctx_for("analyst"), RUN_KIND, aggregate_id=r["id"])
    assert job["payload"] == {"run_id": str(r["id"])} and job["dedupe_key"] == f"run:{r['id']}"
    assert job["created_by"] == world["analyst"]
    w = build_worker(ingestion.db, ingestion, sync, config=WorkerConfig())
    w.run_once(only_tenants={world.a.id})
    [job] = jobs_for(run, ctx_for("analyst"), RUN_KIND, aggregate_id=r["id"])
    assert job["state"] == "succeeded" and job["result"]["status"] == "completed"
    assert job["result"]["coverage"] == "complete"


def test_run_finished_by_a_fenced_out_step_completes_the_job_without_rerunning(world, run, ctx_for, upload, stack,
                                                                            admin_conn):
    """A step whose job lease was lost may still finish the run (its pages are fenced by the run's own lease).
    The next job step must recognise the finished run instead of waiting forever."""
    ingestion, sync = stack
    r = request(world, ctx_for, upload, ingestion)
    ingestion.execute(world.a.id, world.a.system, r["id"], worker_id="out-of-band")      # run finished
    build_worker(ingestion.db, ingestion, sync).run_once(only_tenants={world.a.id})
    [job] = jobs_for(run, ctx_for("analyst"), RUN_KIND, aggregate_id=r["id"])
    assert job["state"] == "succeeded" and job["result"]["already_finished"] is True
    attempts = run(ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT attempts FROM axiom.ingestion_runs WHERE id = %s", (r["id"],)).fetchone()["attempts"])
    assert attempts == 1


def test_run_leased_elsewhere_makes_the_job_wait_not_fail(world, run, ctx_for, upload, stack, admin_conn):
    ingestion, sync = stack
    r = request(world, ctx_for, upload, ingestion)
    admin_conn.execute("""UPDATE axiom.ingestion_runs SET status = 'running', lease_owner = 'other',
                                 lease_token = lease_token + 1, lease_expires_at = clock_timestamp() + interval '1 hour',
                                 record_version = record_version + 1 WHERE id = %s""", (r["id"],))
    build_worker(ingestion.db, ingestion, sync).run_once(only_tenants={world.a.id})
    [job] = jobs_for(run, ctx_for("analyst"), RUN_KIND, aggregate_id=r["id"])
    assert job["state"] == "waiting" and job["wait_reason"] == "run is leased by another worker"


def test_risk_expiry_sweep_is_scheduled_once_per_interval_per_tenant(world, run, ctx_for, stack, db):
    ingestion, sync = stack
    w1 = build_worker(db, ingestion, sync, worker_id="w1", risk_sweep_interval=3600)
    w2 = build_worker(db, ingestion, sync, worker_id="w2", risk_sweep_interval=3600)
    w1.run_once(only_tenants={world.a.id})
    w2.run_once(only_tenants={world.a.id})
    sys_a = ctx_for("system")
    sweeps = jobs_for(run, sys_a, RISK_SWEEP)
    assert len(sweeps) == 1 and sweeps[0]["state"] == "succeeded" and sweeps[0]["result"] == {"expired": [], "lapsed": [], "reassessment_notices": []}
    assert jobs_for(run, ctx_for("system", "b"), RISK_SWEEP) == []          # tenant b was not processed
