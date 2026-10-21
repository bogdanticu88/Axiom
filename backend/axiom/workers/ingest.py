"""Ingestion worker: picks up queued (or lease-expired) runs tenant by tenant.

INTERIM DISPATCHER. Orchestration is pending ADR 0006; this loop only finds work. Correctness does not depend
on it: runs are claimed with a lease and a fencing token, pages are fenced in the database, and committed
pages are skipped on resume, so any orchestrator (or several of these loops) can call execute safely.

  python -m axiom.workers.ingest --once
  python -m axiom.workers.ingest --interval 10
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import time
import uuid

from ..config import Settings
from ..api.app import build_object_store
from ..db import Database, TenantContext
from ..domains.evidence.service import EvidenceService
from ..ingestion.pipeline import IngestionService
from ..ingestion.sync import SyncService

log = logging.getLogger("axiom.workers.ingest")


def ready_runs(db: Database, limit_per_tenant: int = 5) -> list[tuple[TenantContext, dict]]:
    """Ready runs per tenant, a bounded number per tenant per pass (basic fairness)."""
    with db.unbound_tx() as conn:
        tenants = conn.execute("SELECT tenant_id, system_principal_id FROM axiom_auth.active_tenant_workers()").fetchall()
    work = []
    for t in tenants:
        ctx = TenantContext(t["tenant_id"], t["system_principal_id"], "workload", f"worker:{uuid.uuid4()}")
        with db.tenant_tx(ctx) as conn:
            rows = conn.execute(
                """SELECT id, source_kind FROM axiom.ingestion_runs
                    WHERE status IN ('queued', 'running')
                      AND (lease_expires_at IS NULL OR lease_expires_at < clock_timestamp())
                    ORDER BY created_at LIMIT %s""", (limit_per_tenant,)).fetchall()
        work.extend((ctx, r) for r in rows)
    return work


def run_once(db: Database, ingestion: IngestionService, sync: SyncService, worker_id: str) -> int:
    done = 0
    for ctx, run in ready_runs(db):
        try:
            if run["source_kind"] == "file_import":
                result = ingestion.execute(ctx.tenant_id, ctx.principal_id, run["id"], worker_id=worker_id)
            else:
                result = sync.execute_sync(ctx.tenant_id, ctx.principal_id, run["id"], worker_id=worker_id)
            if result is not None:
                done += 1
                log.info("run finished", extra={"run_id": str(run["id"]), "status": result["status"],
                                                "coverage": result["coverage"]})
        except Exception:  # noqa: BLE001 - the run stays leased and is retried after lease expiry
            log.exception("run failed in worker", extra={"run_id": str(run["id"])})
    return done


def main() -> None:
    logging.basicConfig(level=os.environ.get("AXIOM_LOG_LEVEL", "INFO"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=10.0)
    args = parser.parse_args()
    settings = Settings()
    db = Database(settings.database_dsn, min_size=1, max_size=4, name="ingest-worker")
    db.open()
    db.verify_runtime_role()
    store = build_object_store(settings)
    ingestion = IngestionService(db, store)
    sync = SyncService(db, ingestion, EvidenceService(db, store, max_bytes=settings.evidence_max_bytes))
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        run_once(db, ingestion, sync, worker_id)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
