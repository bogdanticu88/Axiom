"""Generic job worker (ADR 0006): ingestion runs, scheduled risk-expiry sweeps, and future job kinds.

  python -m axiom.workers.jobs --once
  python -m axiom.workers.jobs --interval 5

Refuses to start on a database whose fingerprint has not been acknowledged (restored or copied database);
see ``python -m axiom.provisioning recovery-status``.
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import time

from ..api.app import build_object_store
from ..config import Settings
from ..db import Database
from ..domains.cases.jobs import KIND as RISK_SWEEP, RiskExpirySweepHandler
from ..domains.evidence.service import EvidenceService
from ..ingestion.jobs import IngestionRunHandler
from ..ingestion.pipeline import IngestionService
from ..ingestion.sync import SyncService
from ..jobs import Schedule, Worker, WorkerConfig

log = logging.getLogger("axiom.workers.jobs")

RISK_SWEEP_INTERVAL_SECONDS = 3600


def build_worker(db: Database, ingestion: IngestionService, sync: SyncService, *, worker_id: str | None = None,
                 config: WorkerConfig | None = None, risk_sweep_interval: int = RISK_SWEEP_INTERVAL_SECONDS) -> Worker:
    return Worker(db, [IngestionRunHandler(ingestion, sync), RiskExpirySweepHandler()], worker_id=worker_id,
                  config=config, schedules=[Schedule(RISK_SWEEP, 1, risk_sweep_interval)])


def main() -> None:
    logging.basicConfig(level=os.environ.get("AXIOM_LOG_LEVEL", "INFO"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    settings = Settings()
    db = Database(settings.database_dsn, min_size=1, max_size=6, name="job-worker")
    db.open()
    db.verify_runtime_role()
    store = build_object_store(settings)
    ingestion = IngestionService(db, store)
    sync = SyncService(db, ingestion, EvidenceService(db, store, max_bytes=settings.evidence_max_bytes))
    worker = build_worker(db, ingestion, sync, worker_id=f"{socket.gethostname()}:{os.getpid()}")
    worker.preflight()      # fail fast at start-up, not only on the first pass
    while True:
        try:
            worker.run_once()
        except Exception:  # noqa: BLE001 - keep the loop alive; leases make every step safe to retry
            log.exception("worker pass failed")
            if args.once:
                raise
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
