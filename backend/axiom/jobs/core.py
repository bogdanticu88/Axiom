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
# Jobs whose cancellation and effect resolution go through their domain record (JobOperations._settled_elsewhere)
SETTLED_WITH_AGGREGATE = {"action_execution": "/action-executions/{execution_id}/cancel or /reconcile"}


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


def lock_held_lease(conn: psycopg.Connection, job_id, token: int) -> dict | None:
    """The lease authorization check for writes to the job row (the attempt counter, the heartbeat and the final
    write) and for handler transactions that call ``JobContext.fenced``. Call inside a transaction; returns the locked
    job row while this token holds an unexpired lease, otherwise None. Handler writes made without ``fenced`` are not
    covered (see ADR 0006 amendment 1).

    Two steps, because PostgreSQL (READ COMMITTED) evaluates a locking query's WHERE clause before it waits for a
    row lock and, if the transaction it waited for only locked the row, does not evaluate it again. An expiry test
    inside the locking query could therefore pass before a wait and stand after the lease expired during that wait.
    So the row is first locked by token and state, which are re-checked if a transaction it waited for changed them,
    and then, with the lock held, the expiry is tested by the database clock (``clock_timestamp()``, the time of that
    statement). The guarantee is that the lease was valid at that locked check. It does not extend to the commit: the
    lease may expire after the check, but while this transaction holds the lock no other worker can reclaim the job
    (a reclaim needs the same row lock), so whatever this transaction writes is written by the only lease holder."""
    row = conn.execute(
        "SELECT * FROM axiom.jobs WHERE id = %s AND lease_token = %s AND state = 'running' FOR UPDATE",
        (job_id, token)).fetchone()
    if row is None:
        return None
    live = conn.execute("SELECT lease_expires_at > clock_timestamp() AS live FROM axiom.jobs WHERE id = %s",
                        (job_id,)).fetchone()["live"]
    return row if live else None


@dataclass
class JobContext:
    db: Database
    ctx: TenantContext
    job: dict
    lease_token: int
    worker_id: str
    witness: Any = None     # external restore witness (axiom.jobs.witness), passed to the effect gate

    def fenced(self, conn: psycopg.Connection) -> dict:
        """Lock the job row and verify this worker still holds the lease (``lock_held_lease``). Call inside a
        transaction. Writes the handler commits in that transaction stay committed even if the job's outcome is later
        discarded; the lease check does not undo them."""
        row = lock_held_lease(conn, self.job["id"], self.lease_token)
        if row is None:
            raise StaleLease(f"lease {self.lease_token} on job {self.job['id']} is no longer held")
        return row


class Handler(Protocol):
    """A job handler. It may also define ``on_cancel(conn, ctx, job) -> StepResult``: how to settle a job whose
    cancellation was requested, decided from what the handler has on record about its effect. The worker calls it
    with the job row locked, either while claiming the job (no worker holds a valid lease then) or in the final write
    of the worker that holds the lease (``Worker._finish``). Its result is applied by ``settle_cancelled_job``. Without
    ``on_cancel`` a cancelled job is simply marked cancelled."""
    kind: str
    versions: frozenset[int]
    current_version: int

    def step(self, jc: JobContext) -> StepResult: ...


def settle_cancelled_job(conn: psycopg.Connection, ctx: TenantContext, job_id: UUID, outcome: StepResult, *,
                         lease_token: int | None = None, worker: str | None = None) -> None:
    """Final state of a job whose cancellation was requested, from its handler's ``on_cancel`` settlement. Requesting
    cancellation stops further scheduling; it does not establish that an external action was cancelled, so:

    * ``Fail``: nothing was dispatched (or the effect is known to have failed); the job is cancelled.
    * ``Done``: the effect is on record; the job succeeded, because it did.
    * ``NeedsOperator``: a dispatch may have happened and its outcome is unknown; the job is parked for an operator,
      never silently cancelled. ``cancel_requested`` stays set, so the operator's resolution settles it again.

    The caller holds the job row lock and the right to write it (claim, lease holder, or an operator on a job no
    worker holds)."""
    common = ("lease_owner = NULL, lease_expires_at = NULL, step_deadline_at = NULL, updated_at = clock_timestamp(), "
              "record_version = record_version + 1")
    if isinstance(outcome, Done):
        conn.execute(f"UPDATE axiom.jobs SET state = 'succeeded', result = %s, finished_at = clock_timestamp(), "
                     f"{common} WHERE id = %s", (Jsonb(outcome.result), job_id))
        name, detail = "cancel_settled_succeeded", {"result": outcome.result}
    elif isinstance(outcome, NeedsOperator):
        conn.execute(f"UPDATE axiom.jobs SET state = 'needs_operator', operator_reason = %s, {common} WHERE id = %s",
                     (outcome.reason[:2000], job_id))
        name, detail = "cancel_settled_needs_operator", {"reason": outcome.reason}
    elif isinstance(outcome, Fail):
        conn.execute(f"UPDATE axiom.jobs SET state = 'cancelled', last_error = %s, finished_at = clock_timestamp(), "
                     f"{common} WHERE id = %s", (outcome.error[:2000], job_id))
        name, detail = "cancelled", {"error": outcome.error}
    else:
        raise TypeError(f"a cancellation settles as Done, Fail or NeedsOperator, not {outcome!r}")
    event(conn, ctx, job_id, name, lease_token=lease_token, worker=worker, detail=detail)


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

    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer, *,
                 permission: str = "job.operate", scope_id: UUID | None = None, aggregate: str | None = None):
        """``permission``/``scope_id`` let a domain (e.g. action reconciliation) authorise an operator action with
        its own narrower permission at the resource's scope instead of tenant-wide ``job.operate``. ``aggregate``
        names the domain record the caller settles together with the job (see ``SETTLED_WITH_AGGREGATE``)."""
        self.conn, self.ctx, self.authz = conn, ctx, authz
        self.operate_permission = permission
        self.operate_scope = scope_id
        self.aggregate = aggregate

    def _settled_elsewhere(self, job: dict) -> None:
        """Cancelling or resolving the effect of a job that owns a domain record (an action execution and its approval
        use) must change that record in the same transaction; done on the job alone it would leave the record open."""
        where = SETTLED_WITH_AGGREGATE.get(job["aggregate_type"])
        if where and self.aggregate != job["aggregate_type"]:
            raise Conflict(f"this job belongs to {job['aggregate_type']} {job['aggregate_id']}; use {where}",
                           code="settled_with_aggregate")

    def _root(self) -> UUID:
        return self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]

    def _operate(self):
        return self.authz.require(self.operate_permission, self.operate_scope or self._root())

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

    def list(self, *, state: str | None = None, kind: str | None = None, limit: int = 100) -> list[dict]:
        self.authz.require("job.read", self._root())
        return list(self.conn.execute(
            """SELECT id, kind, handler_version, state, attempts, max_attempts, claims, max_claims, operator_retries,
                      due_at, wait_reason, last_error, operator_reason, aggregate_type, aggregate_id, created_at,
                      updated_at, finished_at
                 FROM axiom.jobs WHERE (%(state)s::text IS NULL OR state = %(state)s)
                  AND (%(kind)s::text IS NULL OR kind = %(kind)s)
                ORDER BY updated_at DESC LIMIT %(limit)s""", {"state": state, "kind": kind, "limit": limit}))

    def retry(self, job_id: UUID, rationale: str, *, extra_attempts: int = 3) -> dict:
        """Operator retry. Dead-lettered and failed jobs go back to the queue with a larger budget; a parked job
        (needs_operator) is re-run as is, so its effect gate decides again from the recorded intent. Approvals and
        reservations are never changed here."""
        authority = self._operate()
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        if not 1 <= extra_attempts <= 10:
            raise ValidationFailed("extra_attempts must be 1 to 10")
        job = self._job(job_id)
        if job["state"] in ("dead_lettered", "failed"):
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'queued', operator_retries = operator_retries + 1, due_at = clock_timestamp(),
                          finished_at = NULL, operator_reason = NULL, lease_owner = NULL, lease_expires_at = NULL,
                          max_attempts = LEAST(100, GREATEST(max_attempts, attempts + %s)),
                          max_claims = LEAST(1000, GREATEST(max_claims, claims + %s)),
                          updated_at = clock_timestamp(), record_version = record_version + 1
                    WHERE id = %s RETURNING *""", (extra_attempts, extra_attempts * 2, job_id)).fetchone()
        elif job["state"] == "needs_operator":
            row = self.conn.execute(
                """UPDATE axiom.jobs SET state = 'queued', due_at = clock_timestamp(), operator_reason = NULL,
                          updated_at = clock_timestamp(), record_version = record_version + 1
                    WHERE id = %s RETURNING *""", (job_id,)).fetchone()
        else:
            raise Conflict(f"a {job['state']} job cannot be retried", code="invalid_state")
        event(self.conn, self.ctx, job_id, "operator_retry", detail={"rationale": rationale, "from": job["state"]})
        audit.record(self.conn, self.ctx, action="job.retry", resource_type="job", resource_id=job_id,
                     detail={"rationale": rationale, "from": job["state"], "authority": authority.as_json()})
        return row

    def metrics(self) -> dict:
        """Tenant-level runner metrics (see also axiom.jobs.metrics for the worker's Prometheus endpoint)."""
        self.authz.require("job.read", self._root())
        return collect(self.conn)

    def list_attention(self, limit: int = 100) -> list[dict]:
        self.authz.require("job.read", self._root())
        return list(self.conn.execute(
            """SELECT id, kind, state, operator_reason, last_error, claims, attempts, updated_at FROM axiom.jobs
                WHERE state IN ('needs_operator', 'dead_lettered') ORDER BY updated_at DESC LIMIT %s""", (limit,)))

    def request_cancel(self, job_id: UUID, reason: str) -> dict:
        authority = self._operate()
        job = self._job(job_id)
        self._settled_elsewhere(job)
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
        authority = self._operate()
        if resolution not in ("adopt", "not_applied", "abandon"):
            raise ValidationFailed("resolution must be adopt, not_applied or abandon")
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        job = self._job(job_id)
        self._settled_elsewhere(job)
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
                          db_fingerprint = axiom.db_fingerprint(), recovery_cleared_at = clock_timestamp(),
                          updated_at = clock_timestamp(), record_version = record_version + 1
                    WHERE id = %s RETURNING *""", (job_id,)).fetchone()
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
        authority = self._operate()
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


def collect(conn: psycopg.Connection) -> dict:
    """Runner metrics for the tenant bound to ``conn`` (RLS scopes every query)."""
    by_state = list(conn.execute(
        "SELECT kind, state, count(*) AS n FROM axiom.jobs GROUP BY kind, state ORDER BY kind, state"))
    oldest = conn.execute(
        """SELECT EXTRACT(EPOCH FROM clock_timestamp() - min(due_at)) AS age FROM axiom.jobs
            WHERE state IN ('queued', 'waiting') AND due_at <= clock_timestamp()""").fetchone()["age"]
    events = {r["event"]: r["n"] for r in conn.execute(
        """SELECT event, count(*) AS n FROM axiom.job_events
            WHERE created_at > clock_timestamp() - interval '1 hour'
              AND event IN ('stale_result_discarded', 'dead_lettered_poison', 'effect_needs_operator',
                            'effect_adopted', 'effect_attempt', 'effect_denied', 'operator_retry')
            GROUP BY event""")}
    reclaimed = conn.execute(
        """SELECT count(*) AS n FROM axiom.job_events WHERE event = 'claimed'
            AND created_at > clock_timestamp() - interval '1 hour'
            AND (detail->>'reclaimed_after_expiry')::boolean""").fetchone()["n"]
    return {"jobs_by_kind_state": by_state, "oldest_due_seconds": float(oldest or 0.0),
            "last_hour": {**events, "lease_expiries": reclaimed}}
