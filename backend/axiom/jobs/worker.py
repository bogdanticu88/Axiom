"""Job worker (ADR 0006).

* Tenant by tenant (tenant and system principal from ``axiom_auth.active_tenant_workers``), the worker claims due
  jobs with FOR UPDATE SKIP LOCKED, honouring a per-tenant cap on concurrently running jobs.
* Every claim increments ``claims`` and the fencing ``lease_token``. A job claimed more than ``max_claims``
  times is dead-lettered as poison, even if every previous claim crashed before reaching the handler.
* A lease is held only while its token matches, the job is ``running`` and ``lease_expires_at`` is in the future by
  the database clock; an expired lease is lost and can only be taken again by a new claim, with a new token. Every
  write a lease holder makes to the job row (attempt counter, heartbeat, final write), and every handler transaction
  that calls ``JobContext.fenced``, is authorized by ``core.lock_held_lease``, which tests expiry while holding the
  job's row lock. Handler writes made without ``fenced`` are not covered (ADR 0006 amendment 1).
* A heartbeat thread renews a lease that is still held, and only until the step deadline. It never revives an
  expired lease: a heartbeat that finds the lease lost records ``heartbeat_lease_lost`` and stops. A step that hangs
  past its deadline loses the lease; another worker may then take the job, and anything the hung worker writes later
  is fenced out.
* A lost or expired lease discards the step's outcome and leaves the job for another worker to reclaim. Discarding
  the job's outcome does not undo writes a handler already committed in its own fenced transactions, or effects
  outside the database.
* Handlers declare the versions they run; jobs pinned to other versions are left for other workers.
* A requested cancellation stops scheduling. For a handler with ``on_cancel`` it is settled from the handler's effect
  record, at claim time or in the lease holder's final write, and may end the job succeeded or parked for an operator
  instead of cancelled (``core.settle_cancelled_job``).
"""
from __future__ import annotations

import logging
import random
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from ..db import Database, TenantContext
from .witness import check as witness_check
from .core import (Done, Fail, Handler, JobContext, NeedsOperator, Retry, StaleLease, Wait, enqueue, event,
                   lock_held_lease, settle_cancelled_job)

log = logging.getLogger(__name__)


class RestoreNotAcknowledged(RuntimeError):
    pass


@dataclass(frozen=True)
class Schedule:
    """A recurring per-tenant job. One job per tenant per interval bucket (dedupe key), so any number of
    workers can ensure it without creating duplicates."""
    kind: str
    version: int
    interval_seconds: int

    def dedupe_key(self, now: datetime) -> str:
        return f"schedule:{int(now.timestamp()) // self.interval_seconds}"


@dataclass
class WorkerConfig:
    lease_seconds: float = 60.0
    step_timeout_seconds: float = 300.0
    per_tenant_running_limit: int = 2
    batch_per_tenant: int = 5
    max_backoff_seconds: float = 900.0


class Worker:
    def __init__(self, db: Database, handlers: list[Handler], *, worker_id: str | None = None,
                 config: WorkerConfig | None = None, schedules: list[Schedule] | None = None, witness=None):
        self.db = db
        self.witness = witness
        self.counters: dict[str, int] = {"claimed": 0, "executed": 0, "stale_results_discarded": 0,
                                         "dead_lettered_poison": 0, "handler_errors": 0, "heartbeat_lease_lost": 0}
        self.schedules = list(schedules or [])
        self.handlers = {h.kind: h for h in handlers}
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.config = config or WorkerConfig()

    # --------------------------------------------------------------------------- loop
    def tenants(self) -> list[TenantContext]:
        with self.db.unbound_tx() as conn:
            rows = conn.execute("SELECT tenant_id, system_principal_id FROM axiom_auth.active_tenant_workers()").fetchall()
        return [TenantContext(r["tenant_id"], r["system_principal_id"], "workload", f"{self.worker_id}:{uuid.uuid4()}")
                for r in rows]

    def preflight(self) -> str:
        """Refuse to run on a restored database until an operator has acknowledged it (ADR 0006)."""
        with self.db.unbound_tx() as conn:
            row = conn.execute(
                """SELECT axiom.db_fingerprint() AS f, EXISTS (SELECT 1 FROM axiom.recovery_acknowledgements
                                                            WHERE fingerprint = axiom.db_fingerprint()) AS ok""").fetchone()
        with self.db.unbound_tx() as conn:
            behind = witness_check(conn, self.witness)
        if behind:
            raise RestoreNotAcknowledged(behind + ". Reconcile external effects, then run: python -m "
                                         "axiom.provisioning acknowledge-recovery --witness-dir/--witness-s3 ...")
        if not row["ok"]:
            raise RestoreNotAcknowledged(
                f"database fingerprint {row['f']} has not been acknowledged; this looks like a restored or copied "
                "database. Reconcile external effects, then run: python -m axiom.provisioning "
                "acknowledge-recovery --by ... --note ...")
        return row["f"]

    def run_once(self, only_tenants: set | None = None) -> int:
        """One pass over all tenants (or the given ones). Returns the number of steps executed."""
        self.preflight()
        executed = 0
        for ctx in self.tenants():
            if only_tenants is not None and ctx.tenant_id not in only_tenants:
                continue
            self.ensure_scheduled(ctx)
            for job, token in self.claim(ctx):
                self.execute(ctx, job, token)
                executed += 1
        return executed

    def ensure_scheduled(self, ctx: TenantContext) -> None:
        if not self.schedules:
            return
        now = datetime.now(timezone.utc)
        with self.db.tenant_tx(ctx) as conn:
            for s in self.schedules:
                enqueue(conn, ctx, kind=s.kind, version=s.version, payload={"bucket": s.dedupe_key(now)},
                        dedupe_key=s.dedupe_key(now), max_attempts=3)

    # -------------------------------------------------------------------------- claim
    def _supported_filter(self) -> tuple[str, list]:
        clauses, params = [], []
        for kind, handler in self.handlers.items():
            clauses.append("(kind = %s AND handler_version = ANY(%s))")
            params += [kind, list(handler.versions)]
        return (" OR ".join(clauses) or "false"), params

    def claim(self, ctx: TenantContext, limit: int | None = None) -> list[tuple[dict, int]]:
        cfg = self.config
        supported, params = self._supported_filter()
        claimed: list[tuple[dict, int]] = []
        with self.db.tenant_tx(ctx) as conn:
            running = conn.execute(
                "SELECT count(*) AS n FROM axiom.jobs WHERE state = 'running' AND lease_expires_at > clock_timestamp()"
            ).fetchone()["n"]
            slots = max(0, min(limit or cfg.batch_per_tenant, cfg.per_tenant_running_limit - running))
            if slots == 0:
                return []
            rows = conn.execute(
                f"""SELECT * FROM axiom.jobs
                     WHERE ((state IN ('queued', 'waiting') AND due_at <= clock_timestamp())
                            OR (state = 'running' AND lease_expires_at <= clock_timestamp()))
                       AND ({supported})
                     ORDER BY due_at, created_at LIMIT %s FOR UPDATE SKIP LOCKED""",
                (*params, slots)).fetchall()
            for job in rows:
                settle = getattr(self.handlers[job["kind"]], "on_cancel", None)
                if job["cancel_requested"] and settle is not None:
                    # the claim holds the row lock and no worker holds a valid lease: the handler settles the job
                    # from what it has on record about its effect (see Handler, settle_cancelled_job)
                    try:
                        with conn.transaction():     # a savepoint: one job that cannot be settled stays as it is
                            settle_cancelled_job(conn, ctx, job["id"], settle(conn, ctx, job, self.witness),
                                                 worker=self.worker_id)
                    except Exception:  # noqa: BLE001 - left for the next claim; never cancelled without settling
                        log.exception("cancellation could not be settled", extra={"job_id": str(job["id"])})
                    continue
                if job["cancel_requested"]:
                    conn.execute(
                        """UPDATE axiom.jobs SET state = 'cancelled', finished_at = clock_timestamp(), lease_owner = NULL,
                                  updated_at = clock_timestamp(), record_version = record_version + 1 WHERE id = %s""",
                        (job["id"],))
                    event(conn, ctx, job["id"], "cancelled", worker=self.worker_id)
                    continue
                if job["claims"] + 1 > job["max_claims"]:
                    conn.execute(
                        """UPDATE axiom.jobs SET state = 'dead_lettered', claims = claims + 1, finished_at = clock_timestamp(),
                                  last_error = %s, lease_owner = NULL, lease_expires_at = NULL,
                                  updated_at = clock_timestamp(), record_version = record_version + 1 WHERE id = %s""",
                        (f"poison: claimed {job['claims'] + 1} times without finishing", job["id"]))
                    self.counters["dead_lettered_poison"] += 1
                    event(conn, ctx, job["id"], "dead_lettered_poison", worker=self.worker_id,
                          detail={"claims": job["claims"] + 1})
                    continue
                updated = conn.execute(
                    """UPDATE axiom.jobs SET state = 'running', claims = claims + 1, lease_token = lease_token + 1,
                              lease_owner = %s, lease_expires_at = clock_timestamp() + make_interval(secs => %s),
                              step_deadline_at = clock_timestamp() + make_interval(secs => %s), wait_reason = NULL,
                              updated_at = clock_timestamp(), record_version = record_version + 1
                        WHERE id = %s RETURNING *""",
                    (self.worker_id, min(cfg.lease_seconds, cfg.step_timeout_seconds), cfg.step_timeout_seconds,
                     job["id"])).fetchone()
                event(conn, ctx, job["id"], "claimed", lease_token=updated["lease_token"], worker=self.worker_id,
                      detail={"claims": updated["claims"], "reclaimed_after_expiry": job["state"] == "running"})
                claimed.append((updated, updated["lease_token"]))
                self.counters["claimed"] += 1
        return claimed

    # ------------------------------------------------------------------------ execute
    def _renew(self, ctx: TenantContext, job_id, token: int) -> bool:
        """One heartbeat. Renews the lease only if this token still holds it (``lock_held_lease``: matching token,
        running, unexpired, checked with the row lock held) and the step deadline has not passed; the renewed lease
        never extends past the step deadline. Otherwise records why the lease is lost and returns False."""
        with self.db.tenant_tx(ctx) as conn:
            held = lock_held_lease(conn, job_id, token)
            if held is not None:
                row = conn.execute(
                    """UPDATE axiom.jobs SET lease_expires_at = LEAST(clock_timestamp() + make_interval(secs => %s),
                                                                     step_deadline_at),
                              updated_at = clock_timestamp(), record_version = record_version + 1
                        WHERE id = %s AND step_deadline_at > clock_timestamp()
                    RETURNING id""", (self.config.lease_seconds, job_id)).fetchone()
                if row is not None:
                    return True
            now = conn.execute(
                """SELECT lease_token, state, lease_expires_at > clock_timestamp() AS unexpired,
                          step_deadline_at > clock_timestamp() AS before_deadline
                     FROM axiom.jobs WHERE id = %s""", (job_id,)).fetchone()
            reason = ("reclaimed by a later claim" if now["lease_token"] != token
                      else f"job is {now['state']}" if now["state"] != "running"
                      else "lease expired" if not now["unexpired"]
                      else "step deadline passed")
            self.counters["heartbeat_lease_lost"] += 1
            event(conn, ctx, job_id, "heartbeat_lease_lost", lease_token=token, worker=self.worker_id,
                  detail={"reason": reason})
        log.warning("heartbeat found the lease lost; not renewed", extra={"job_id": str(job_id), "reason": reason})
        return False

    def _heartbeat(self, ctx: TenantContext, job_id, token: int, stop: threading.Event) -> None:
        interval = max(0.2, self.config.lease_seconds / 3)
        while not stop.wait(interval):
            try:
                if not self._renew(ctx, job_id, token):
                    return   # lease lost or step deadline passed: reported, never revived
            except Exception:  # noqa: BLE001 - the lease simply expires
                log.exception("heartbeat failed")
                return

    def execute(self, ctx: TenantContext, job: dict, token: int) -> None:
        handler = self.handlers[job["kind"]]
        jc = JobContext(self.db, ctx, job, token, self.worker_id, self.witness)
        try:
            with self.db.tenant_tx(ctx) as conn:
                jc.fenced(conn)
                conn.execute("""UPDATE axiom.jobs SET attempts = attempts + 1, updated_at = clock_timestamp(),
                                       record_version = record_version + 1 WHERE id = %s""", (job["id"],))
        except StaleLease:
            return
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(ctx, job["id"], token, stop), daemon=True)
        beat.start()
        try:
            try:
                outcome = handler.step(jc)
            except StaleLease:
                self._record_stale(ctx, job, token, "handler detected lost lease")
                return
            except Exception as exc:  # noqa: BLE001 - unexpected handler errors are retried with backoff
                log.exception("job step raised", extra={"job_id": str(job["id"])})
                self.counters["handler_errors"] += 1
                outcome = Retry(f"{type(exc).__name__}: {exc}")
        finally:
            stop.set()
            beat.join(timeout=5)
        self.counters["executed"] += 1
        self._finish(ctx, job, token, outcome)

    def _record_stale(self, ctx, job, token, why: str) -> None:
        with self.db.tenant_tx(ctx) as conn:
            event(conn, ctx, job["id"], "stale_result_discarded", lease_token=token, worker=self.worker_id,
                  detail={"why": why})

    def _finish(self, ctx: TenantContext, job: dict, token: int, outcome) -> None:
        cfg = self.config
        with self.db.tenant_tx(ctx) as conn:
            # The final write's authorization: the lease must be valid at the locked check in lock_held_lease (see
            # its docstring). It may expire after that check and before the commit; no other worker can reclaim the job
            # meanwhile, because this transaction holds the row lock a reclaim needs.
            current = lock_held_lease(conn, job["id"], token)
            if current is None:
                self.counters["stale_results_discarded"] += 1
                event(conn, ctx, job["id"], "stale_result_discarded", lease_token=token, worker=self.worker_id,
                      detail={"outcome": type(outcome).__name__})
                return
            settle = getattr(self.handlers[job["kind"]], "on_cancel", None)
            if current["cancel_requested"] and not isinstance(outcome, Done) and settle is not None:
                settle_cancelled_job(conn, ctx, job["id"], settle(conn, ctx, current, self.witness),
                                     lease_token=token, worker=self.worker_id)
                return
            if current["cancel_requested"] and not isinstance(outcome, Done):
                outcome = Fail("cancelled")
                conn.execute("""UPDATE axiom.jobs SET state = 'cancelled', last_error = 'cancelled', finished_at = clock_timestamp(),
                                       lease_owner = NULL, lease_expires_at = NULL, step_deadline_at = NULL,
                                       updated_at = clock_timestamp(), record_version = record_version + 1
                                 WHERE id = %s""", (job["id"],))
                event(conn, ctx, job["id"], "cancelled", lease_token=token, worker=self.worker_id)
                return
            common = "lease_owner = NULL, lease_expires_at = NULL, step_deadline_at = NULL, updated_at = clock_timestamp(), record_version = record_version + 1"
            if isinstance(outcome, Done):
                conn.execute(f"UPDATE axiom.jobs SET state = 'succeeded', result = %s, finished_at = clock_timestamp(), "
                             f"{common} WHERE id = %s", (Jsonb(outcome.result), job["id"]))
            elif isinstance(outcome, Wait):
                conn.execute(f"UPDATE axiom.jobs SET state = 'waiting', due_at = %s, wait_reason = %s, {common} "
                             f"WHERE id = %s", (outcome.until, outcome.reason[:500], job["id"]))
            elif isinstance(outcome, Retry):
                if current["attempts"] >= current["max_attempts"]:
                    conn.execute(f"UPDATE axiom.jobs SET state = 'dead_lettered', last_error = %s, "
                                 f"finished_at = clock_timestamp(), {common} WHERE id = %s",
                                 (outcome.error[:2000], job["id"]))
                else:
                    backoff = min(cfg.max_backoff_seconds, 2 ** current["attempts"]) * random.uniform(0.8, 1.2)
                    due = datetime.now(timezone.utc) + timedelta(seconds=backoff)
                    conn.execute(f"UPDATE axiom.jobs SET state = 'queued', due_at = %s, last_error = %s, {common} "
                                 f"WHERE id = %s", (due, outcome.error[:2000], job["id"]))
            elif isinstance(outcome, Fail):
                conn.execute(f"UPDATE axiom.jobs SET state = 'failed', last_error = %s, finished_at = clock_timestamp(), "
                             f"{common} WHERE id = %s", (outcome.error[:2000], job["id"]))
            elif isinstance(outcome, NeedsOperator):
                conn.execute(f"UPDATE axiom.jobs SET state = 'needs_operator', operator_reason = %s, {common} "
                             f"WHERE id = %s", (outcome.reason[:2000], job["id"]))
            else:
                raise TypeError(f"unknown step outcome {outcome!r}")
            event(conn, ctx, job["id"], type(outcome).__name__.lower(), lease_token=token, worker=self.worker_id,
                  detail={k: (v.isoformat() if isinstance(v, datetime) else v)
                          for k, v in outcome.__dict__.items()})
