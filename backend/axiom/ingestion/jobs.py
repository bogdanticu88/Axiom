"""Ingestion on the job runner (ADR 0006).

A run request enqueues one ``ingestion.run`` job in the same transaction as the run row. The job step claims the
run through the pipeline's own lease and fencing token, so page commits stay fenced by the database regardless of
which job worker executes them. The job layer adds durable dispatch, bounded retries, dead-lettering, operator
visibility and per-tenant fairness.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg

from ..db import TenantContext
from ..jobs import Done, Fail, JobContext, Wait, enqueue
from .pipeline import IngestionService
from .sync import SyncService

KIND = "ingestion.run"
VERSION = 1
TERMINAL_RUN = ("completed", "failed", "cancelled")   # axiom.ingestion_runs.status (0003)


def enqueue_run(conn: psycopg.Connection, ctx: TenantContext, run_id: UUID) -> dict:
    return enqueue(conn, ctx, kind=KIND, version=VERSION, payload={"run_id": str(run_id)},
                   dedupe_key=f"run:{run_id}", aggregate=("ingestion_run", run_id), max_attempts=5, max_claims=10)


class IngestionRunHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = VERSION

    def __init__(self, ingestion: IngestionService, sync: SyncService):
        self.ingestion, self.sync = ingestion, sync

    def step(self, jc: JobContext):
        run_id = UUID(jc.job["payload"]["run_id"])
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            run = conn.execute("SELECT id, source_kind, status FROM axiom.ingestion_runs WHERE id = %s",
                               (run_id,)).fetchone()
        if run is None:
            return Fail("ingestion run not found")
        if run["status"] in TERMINAL_RUN:          # finished by an earlier step whose job result was fenced out
            return Done({"run_id": str(run_id), "status": run["status"], "already_finished": True})
        worker = f"{jc.worker_id}:job{jc.lease_token}"
        if run["source_kind"] == "file_import":
            result = self.ingestion.execute(jc.ctx.tenant_id, jc.ctx.principal_id, run_id, worker_id=worker)
        else:
            result = self.sync.execute_sync(jc.ctx.tenant_id, jc.ctx.principal_id, run_id, worker_id=worker)
        if result is None:   # another worker holds the run's own lease; look again after it could expire
            return Wait(datetime.now(timezone.utc) + timedelta(seconds=self.ingestion.lease_seconds),
                        "run is leased by another worker")
        return Done({"run_id": str(run_id), "status": result["status"], "coverage": result["coverage"]})
