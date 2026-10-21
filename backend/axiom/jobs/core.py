"""Job model: step results, handler contract, enqueueing and operator actions (ADR 0006).

A handler runs one *step* of a job and returns what should happen next. Handlers must be written so that
re-running a step after a crash is safe: any external effect goes through ``EffectGate``
(axiom.jobs.effects), which records intent, reconciles and fences.

Job payloads carry identifiers only (tenant-scoped IDs, digests), never evidence content or secrets.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .. import audit
from ..access import Authorizer
from ..db import Database, TenantContext
from ..errors import Conflict, NotFound, ValidationFailed

TERMINAL = ("succeeded", "failed", "dead_lettered", "cancelled")


@dataclass(frozen=True)
class Done:
    result: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Wait:
    until: datetime
    reason: str


@dataclass(frozen=True)
class Retry:
    error: str


@dataclass(frozen=True)
class Fail:
    error: str


@dataclass(frozen=True)
class NeedsOperator:
    reason: str


StepResult = Done | Wait | Retry | Fail | NeedsOperator


class StaleLease(Exception):
    """The worker no longer holds the job's lease; it must stop and write nothing further."""


@dataclass
class JobContext:
    db: Database
    ctx: TenantContext
    job: dict
    lease_token: int
    worker_id: str

    def fenced(self, conn: psycopg.Connection) -> dict:
        """Lock the job row and verify this worker still holds the lease. Call inside a transaction."""
        row = conn.execute(
            """SELECT * FROM axiom.jobs WHERE id = %s AND lease_token = %s AND state = 'running'
                 AND lease_expires_at > clock_timestamp() FOR UPDATE""",
            (self.job["id"], self.lease_token)).fetchone()
        if row is None:
            raise StaleLease(f"lease {self.lease_token} on job {self.job['id']} is no longer held")
        return row


class Handler(Protocol):
    kind: str
    versions: frozenset[int]
    current_version: int

    def step(self, jc: JobContext) -> StepResult: ...


def enqueue(conn: psycopg.Connection, ctx: TenantContext, *, kind: str, version: int, payload: dict[str, Any],
            due_at: datetime | None = None, dedupe_key: str | None = None, max_attempts: int = 5,
            max_claims: int = 10, aggregate: tuple[str, UUID] | None = None) -> dict:
    """Enqueue inside the caller's transaction. With a dedupe key, an existing job is returned instead."""
    for value in payload.values():
        if isinstance(value, (bytes, bytearray)) or (isinstance(value, str) and len(value) > 512):
            raise ValidationFailed("job payloads carry identifiers only")
    row = conn.execute(
        """INSERT INTO axiom.jobs(tenant_id, id, kind, handler_version, state, dedupe_key, payload, aggregate_type,
               aggregate_id, due_at, max_attempts, max_claims, created_by)
           VALUES (%s, %s, %s, %s, 'queued', %s, %s, %s, %s, COALESCE(%s, clock_timestamp()), %s, %s, %s)
           ON CONFLICT (tenant_id, kind, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING RETURNING *""",
        (ctx.tenant_id, uuid.uuid4(), kind, version, dedupe_key, Jsonb(payload),
         aggregate[0] if aggregate else None, aggregate[1] if aggregate else None, due_at, max_attempts,
         max_claims, ctx.principal_id)).fetchone()
    if row is None:
        row = conn.execute("SELECT * FROM axiom.jobs WHERE kind = %s AND dedupe_key = %s",
                           (kind, dedupe_key)).fetchone()
    else:
        event(conn, ctx, row["id"], "enqueued", detail={"kind": kind, "version": version})
    return row


def event(conn: psycopg.Connection, ctx: TenantContext, job_id: UUID, name: str, *, lease_token: int | None = None,
          worker: str | None = None, detail: dict | None = None) -> None:
    conn.execute(
        """INSERT INTO axiom.job_events(tenant_id, job_id, id, event, lease_token, worker, detail)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (ctx.tenant_id, job_id, uuid.uuid4(), name, lease_token, worker, Jsonb(detail or {})))


class JobOperations:
    """Human operations on jobs: inspect, cancel, resolve parked effects, migrate handler versions."""

    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    def _root(self) -> UUID:
        return self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]

    def _job(self, job_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.jobs WHERE id = %s FOR UPDATE", (job_id,)).fetchone()
        if row is None:
            raise NotFound("job not found", code="job_not_found")
        return row

    def get(self, job_id: UUID) -> dict:
        self.authz.require("job.read", self._root())
        job = dict(self._job(job_id))
        job["events"] = list(self.conn.execute(
            "SELECT event, lease_token, worker, detail, created_at FROM axiom.job_events WHERE job_id = %s "
            "ORDER BY created_at, id", (job_id,)))
        job["intents"] = list(self.conn.execute(
            "SELECT * FROM axiom.effect_intents WHERE job_id = %s ORDER BY created_at", (job_id,)))
        return job

    def list_attention(self, limit: int = 100) -> list[dict]:
        self.authz.require("job.read", self._root())
        return list(self.conn.execute(
            """SELECT id, kind, state, operator_reason, last_error, claims, attempts, updated_at FROM axiom.jobs
                WHERE state IN ('needs_operator', 'dead_lettered') ORDER BY updated_at DESC LIMIT %s""", (limit,)))

    def request_cancel(self, job_id: UUID, reason: str) -> dict:
        authority = self.authz.require("job.operate", self._root())
        job = self._job(job_id)
        if job["state"] in TERMINAL:
            raise Conflict("job already finished", code="job_finished")
        if job["state"] in ("queued", "waiting", "needs_operator"):
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'cancelled', cancel_requested = true, finished_at = clock_timestamp(),
                          updated_at = clock_timestamp(), record_version = record_version + 1 WHERE id = %s RETURNING *""",
                (job_id,)).fetchone()
        else:   # running: the worker sees the flag at its next fenced check and stops before any effect
            row = self.conn.execute(
                """UPDATE axiom.jobs SET cancel_requested = true, updated_at = clock_timestamp(),
                          record_version = record_version + 1 WHERE id = %s RETURNING *""", (job_id,)).fetchone()
        event(self.conn, self.ctx, job_id, "cancel_requested", detail={"reason": reason})
        audit.record(self.conn, self.ctx, action="job.cancel", resource_type="job", resource_id=job_id,
                     detail={"reason": reason, "authority": authority.as_json()})
        return row

    def resolve_effect(self, job_id: UUID, *, resolution: str, rationale: str,
                       external_ref: str | None = None) -> dict:
        """Operator decision for an effect whose outcome could not be determined automatically.

        'adopt' records the external object the operator found; 'not_applied' lets the job retry;
        'abandon' fails the job without an effect.
        """
        authority = self.authz.require("job.operate", self._root())
        if resolution not in ("adopt", "not_applied", "abandon"):
            raise ValidationFailed("resolution must be adopt, not_applied or abandon")
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        job = self._job(job_id)
        if job["state"] != "needs_operator":
            raise Conflict("job is not waiting for an operator", code="invalid_state")
        intent = self.conn.execute(
            """SELECT * FROM axiom.effect_intents WHERE job_id = %s AND state IN ('prepared', 'executing', 'unknown')
                ORDER BY created_at DESC LIMIT 1""", (job_id,)).fetchone()
        if resolution == "adopt" and not external_ref:
            raise ValidationFailed("adopting requires the external reference")
        if intent is not None:
            new_state = {"adopt": "reconciled", "not_applied": "prepared", "abandon": "abandoned"}[resolution]
            self.conn.execute(
                """UPDATE axiom.effect_intents SET state = %s, external_ref = COALESCE(%s, external_ref), resolution = %s,
                          resolved_by = %s, db_fingerprint = axiom.db_fingerprint(), updated_at = clock_timestamp(),
                          record_version = record_version + 1
                    WHERE id = %s""",
                (new_state, external_ref, f"{resolution}: {rationale}", self.ctx.principal_id, intent["id"]))
        if resolution == "abandon":
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'failed', operator_reason = NULL, last_error = %s,
                          finished_at = clock_timestamp(), updated_at = clock_timestamp(),
                          record_version = record_version + 1 WHERE id = %s RETURNING *""",
                (f"abandoned by operator: {rationale}", job_id)).fetchone()
        elif resolution == "adopt" and intent is None:
            # parked across a restore before any intent existed: the operator found the effect, so the job is done
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'succeeded', operator_reason = NULL, result = %s,
                          finished_at = clock_timestamp(), updated_at = clock_timestamp(),
                          record_version = record_version + 1 WHERE id = %s RETURNING *""",
                (Jsonb({"external_ref": external_ref, "adopted_by_operator": True}), job_id)).fetchone()
        else:
            # the operator has reconciled this job against the current database
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'queued', due_at = clock_timestamp(), operator_reason = NULL,
                          db_fingerprint = axiom.db_fingerprint(), updated_at = clock_timestamp(),
                          record_version = record_version + 1 WHERE id = %s RETURNING *""", (job_id,)).fetchone()
        event(self.conn, self.ctx, job_id, f"operator_{resolution}", detail={"rationale": rationale,
                                                                            "external_ref": external_ref})
        audit.record(self.conn, self.ctx, action=f"job.effect_{resolution}", resource_type="job", resource_id=job_id,
                     detail={"rationale": rationale, "external_ref": external_ref, "authority": authority.as_json()})
        return row

    def drain_status(self) -> list[dict]:
        self.authz.require("job.read", self._root())
        return list(self.conn.execute(
            """SELECT kind, handler_version, state, count(*) AS n FROM axiom.jobs WHERE state <> ALL(%s)
                GROUP BY kind, handler_version, state ORDER BY kind, handler_version""", (list(TERMINAL),)))

    def migrate_version(self, job_id: UUID, to_version: int, rationale: str) -> dict:
        authority = self.authz.require("job.operate", self._root())
        job = self._job(job_id)
        if job["state"] in TERMINAL or job["state"] == "running":
            raise Conflict("only queued, waiting or parked jobs can be migrated", code="invalid_state")
        row = self.conn.execute(
            """UPDATE axiom.jobs SET handler_version = %s, updated_at = clock_timestamp(),
                      record_version = record_version + 1 WHERE id = %s RETURNING *""", (to_version, job_id)).fetchone()
        event(self.conn, self.ctx, job_id, "version_migrated",
              detail={"from": job["handler_version"], "to": to_version, "rationale": rationale})
        audit.record(self.conn, self.ctx, action="job.migrate_version", resource_type="job", resource_id=job_id,
                     detail={"from": job["handler_version"], "to": to_version, "authority": authority.as_json()})
        return row
