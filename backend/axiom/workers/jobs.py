"""Generic job worker (ADR 0006): ingestion runs, action executions, scheduled risk-expiry sweeps.

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
from ..domains.actions.jobs import ActionExecuteHandler
from ..domains.actions.sync import KIND as TICKET_SYNC, TicketSyncHandler
from ..domains.cases.jobs import KIND as RISK_SWEEP, RiskExpirySweepHandler
from ..domains.cases.ownership import SWEEP_KIND as OWNERSHIP_SWEEP, OwnershipSweepHandler
from ..domains.cases.sla import KIND as SLA_SWEEP, SlaSweepHandler
from ..errors import ConfigurationError
from ..domains.evidence.service import EvidenceService
from ..ingestion.jobs import IngestionRunHandler
from ..ingestion.pipeline import IngestionService
from ..ingestion.sync import SyncService
from ..jobs import Schedule, Worker, WorkerConfig

log = logging.getLogger("axiom.workers.jobs")

RISK_SWEEP_INTERVAL_SECONDS = 3600
SLA_SWEEP_INTERVAL_SECONDS = 900
TICKET_SYNC_INTERVAL_SECONDS = 900


def build_worker(db: Database, ingestion: IngestionService, sync: SyncService, *, worker_id: str | None = None,
                 config: WorkerConfig | None = None, risk_sweep_interval: int = RISK_SWEEP_INTERVAL_SECONDS,
                 action_handler: ActionExecuteHandler | None = None, witness=None,
                 ticket_sync: TicketSyncHandler | None = None) -> Worker:
    return Worker(db, [IngestionRunHandler(ingestion, sync), RiskExpirySweepHandler(),
                       action_handler or ActionExecuteHandler(), ticket_sync or TicketSyncHandler(), SlaSweepHandler(), OwnershipSweepHandler()],
                  worker_id=worker_id, config=config,
                  schedules=[Schedule(RISK_SWEEP, 1, risk_sweep_interval),
                             Schedule(SLA_SWEEP, 1, SLA_SWEEP_INTERVAL_SECONDS),
                             Schedule(TICKET_SYNC, 1, TICKET_SYNC_INTERVAL_SECONDS),
                             Schedule(OWNERSHIP_SWEEP, 1, SLA_SWEEP_INTERVAL_SECONDS)],
                  witness=witness)


def build_witness(settings: Settings, worker_id: str, *, s3_client=None):
    """Build the restore witness from AXIOM_RESTORE_WITNESS. Refuses (ConfigurationError) when it is required but
    missing, malformed or unusable; never silently falls back to running without one in production."""
    from ..jobs.witness import FileWitness, S3Witness, WitnessUnavailable
    spec = (settings.restore_witness or "").strip()
    if not spec:
        if settings.env == "production":
            raise ConfigurationError("AXIOM_RESTORE_WITNESS is required in production (ADR 0010)")
        return None
    kind, _, where = spec.partition(":")
    where = where.strip()
    try:
        if kind == "dir" and where:
            witness = FileWitness(where, worker_id)
        elif kind == "s3" and where and not where.startswith("/"):
            bucket, _, prefix = where.partition("/")
            if s3_client is None:
                import boto3
                s3_client = boto3.client("s3", endpoint_url=settings.s3_endpoint_url, region_name=settings.s3_region)
            witness = S3Witness(s3_client, bucket, prefix or "restore-witness", worker_id)
        else:
            raise ConfigurationError("AXIOM_RESTORE_WITNESS must be dir:/path or s3:bucket/prefix")
        witness.probe()
    except (WitnessUnavailable, OSError, ValueError) as exc:
        raise ConfigurationError(f"restore witness unusable, refusing to start: {exc}") from exc
    return witness


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
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    worker = build_worker(db, ingestion, sync, worker_id=worker_id, witness=build_witness(settings, worker_id))
    worker.preflight()      # fail fast at start-up, not only on the first pass
    if settings.worker_metrics_port:
        from ..jobs.metrics import serve
        serve(worker, settings.worker_metrics_port)
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
