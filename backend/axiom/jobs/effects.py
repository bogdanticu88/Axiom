"""Effect gate: the only way a job step may cause an external effect (Plan S 7, B07, B08, ADR 0006, ADR 0010).

One effect is identified by a stable ``operation_key``. The gate:

1. In a fenced transaction: checks the lease, cancellation and ``revalidate`` (current authority, approval,
   preconditions), loads or creates the intent row, and detects a restored database. A requested cancellation ends
   the step before any dispatch is authorized (here and in step 3); that is not a statement about an earlier attempt,
   which the handler settles from the recorded evidence (``Handler.on_cancel``).
2. Decides whether another create attempt is safe. That depends on what the integration can do:

   * ``dedupe``: ``idempotency_key`` (the provider returns the original object for a repeated key) or
     ``unique_external_id`` (the provider refuses a second object carrying the operation key) make a repeated create
     harmless; ``none`` does not.
   * ``lookup``: ``strong`` (read-after-write consistent), ``eventual`` (e.g. a search index), or ``none``.
     A lookup *hit* is proof and is adopted. A lookup *miss* is never proof that no effect exists: the index may be
     stale, or a stale worker may still be about to send its request.
   * ``provider_fencing``: the provider rejects requests carrying a lower fencing token than one it has seen.

   A first attempt (intent ``prepared``) may create. Once an attempt may have reached the provider (intent
   ``executing`` or ``unknown``, or the database was restored), the gate creates again **only** if the provider
   deduplicates or fences. Otherwise a lookup hit is adopted and a miss parks the job for an operator.
3. Marks the intent ``executing`` in a fenced transaction that re-reads the intent under lock, so two workers that
   both saw ``prepared`` cannot both send a first attempt. The same transaction draws an effect watermark, which an
   optional external ``RestoreWitness`` records before the request is sent (restore detection, ADR 0010).
4. Calls the provider with the operation key as idempotency key / external identifier and the lease token as
   fencing token, then records succeeded / failed / unknown / definitely-not-applied.

Guarantees and limits (ADR 0010): the platform sends at most one first attempt per operation key, and never sends a
repeat to a provider that cannot deduplicate or fence. A worker that loses its lease *after* step 3 can still deliver
its request; discarding its result afterwards cannot undo that. Only provider deduplication or fencing stops that
duplicate; without them the platform detects the uncertainty and requires reconciliation instead of creating again.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg

from .core import Done, Fail, JobContext, NeedsOperator, Retry, StaleLease, StepResult, event
from .witness import WitnessUnavailable, check as witness_check


class DefinitelyNotApplied(Exception):
    """The integration guarantees the request had no effect (e.g. rejected before processing). Safe to retry."""


class PermanentFailure(Exception):
    """The integration rejected the request; retrying the same request will not help."""


class UnknownOutcome(Exception):
    """The request may or may not have taken effect (timeout after send, connection reset, ambiguous 5xx)."""


class AlreadyExists(Exception):
    """A unique-external-id provider refused a second object; ``ref`` identifies the existing one."""

    def __init__(self, ref: str):
        super().__init__(ref)
        self.ref = ref


class EffectAdapter(Protocol):
    integration: str
    dedupe: str            # 'none' | 'idempotency_key' | 'unique_external_id'
    lookup: str            # 'none' | 'strong' | 'eventual'
    provider_fencing: bool

    def find(self, operation_key: str) -> str | None: ...

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str: ...


def capabilities(adapter) -> tuple[str, str, bool]:
    """Read capabilities; older adapters that only declare ``lookup_supported`` mean strong lookup, no dedupe."""
    lookup = getattr(adapter, "lookup", None)
    if not isinstance(lookup, str):
        lookup = "strong" if getattr(adapter, "lookup_supported", False) else "none"
    return getattr(adapter, "dedupe", "none"), lookup, bool(getattr(adapter, "provider_fencing", False))


def _find(adapter, key: str) -> str | None:
    fn = getattr(adapter, "find", None) or getattr(adapter, "lookup")
    return fn(key)


def operation_key(job_id, request: dict[str, Any]) -> str:
    return hashlib.sha256(f"{job_id}|{canonical(request)}".encode()).hexdigest()


def canonical(request: dict[str, Any]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), default=str)


def restore_doubt(conn: psycopg.Connection, job: dict, intent: dict | None) -> str | None:
    """Why this database cannot vouch that its effect records for ``job`` are complete, or None (ADR 0010).

    A restored or copied database may have lost intents written after its backup, so there a missing intent, or a
    ``prepared`` one, is not evidence that nothing was sent. The signals are the database's own: a fingerprint other
    than the current one on the intent or the job, an unacknowledged fingerprint, or a job created before the latest
    recovery acknowledgement and not reconciled since. The external witness is checked separately
    (``witness.check``), by the gate and by the worker's preflight."""
    fingerprint = conn.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]
    if intent is not None and intent["db_fingerprint"] != fingerprint:
        return "the effect intent was recorded under another database fingerprint"
    if job["db_fingerprint"] != fingerprint:
        return "the job was enqueued or last reconciled under another database fingerprint"
    if conn.execute("SELECT 1 FROM axiom.recovery_acknowledgements WHERE fingerprint = %s",
                    (fingerprint,)).fetchone() is None:
        return "this database fingerprint has not been acknowledged"
    last_ack = conn.execute("SELECT max(acknowledged_at) AS t FROM axiom.recovery_acknowledgements").fetchone()["t"]
    if (last_ack is not None and job["created_at"] < last_ack
            and (job["recovery_cleared_at"] is None or job["recovery_cleared_at"] < last_ack)):
        return "the job predates the latest recovery acknowledgement and has not been reconciled since"
    return None


def unaccounted_dispatches(conn: psycopg.Connection, job_id) -> list[int]:
    """Lease tokens of dispatches this job's gate authorized (``effect_attempt``) whose request is not known to have
    had no effect. An attempt is accounted for when the provider reported it definitely not applied (``effect_prepared``
    or ``effect_prepared_from_stale_attempt`` with the same token) or when an operator later resolved the effect as
    not applied. Read from the append-only job events, which the gate writes in the transaction that authorizes the
    dispatch. An empty list means every authorized dispatch is accounted for, not that no response was received."""
    rows = conn.execute(
        """SELECT a.lease_token FROM axiom.job_events a
            WHERE a.job_id = %(job)s AND a.event = 'effect_attempt'
              AND a.created_at > COALESCE((SELECT max(created_at) FROM axiom.job_events
                                            WHERE job_id = %(job)s AND event = 'operator_not_applied'), '-infinity')
              AND NOT EXISTS (SELECT 1 FROM axiom.job_events n
                               WHERE n.job_id = a.job_id AND n.lease_token = a.lease_token AND n.created_at > a.created_at
                                 AND n.event IN ('effect_prepared', 'effect_prepared_from_stale_attempt'))
            ORDER BY a.created_at""", {"job": job_id}).fetchall()
    return [r["lease_token"] for r in rows]


class RestoreWitness(Protocol):
    """Records effect watermarks outside the database (ADR 0010)."""

    def advance(self, watermark: int) -> None: ...

    def high_water(self) -> int | None: ...


@dataclass
class EffectOutcome:
    step: StepResult
    external_ref: str | None
    how: str | None = None        # 'created' | 'adopted_by_lookup' | 'adopted_by_operator' | 'recorded'


class EffectGate:
    def __init__(self, jc: JobContext, witness: RestoreWitness | None = None):
        self.jc = jc
        self.witness = witness if witness is not None else jc.witness

    def _intent(self, conn: psycopg.Connection, key: str) -> dict | None:
        return conn.execute("SELECT * FROM axiom.effect_intents WHERE operation_key = %s FOR UPDATE", (key,)).fetchone()

    def _job_key_share(self, conn) -> None:
        """Unfenced observation writes lock the job row (KEY SHARE, which the job-event insert needs anyway) before the
        intent, the order every other writer uses (job, then execution, then intent). Without it, an observation
        holding the intent could deadlock against a cancellation settlement holding the job row. No lease needed."""
        conn.execute("SELECT 1 FROM axiom.jobs WHERE id = %s FOR KEY SHARE", (self.jc.job["id"],))

    def _update(self, conn, intent_id, **fields) -> None:
        sets = ", ".join(f"{k} = %({k})s" for k in fields)
        conn.execute(f"UPDATE axiom.effect_intents SET {sets}, updated_at = clock_timestamp(), "
                     f"record_version = record_version + 1 WHERE id = %(id)s", {**fields, "id": intent_id})

    def _park(self, conn, key: str, reason: str) -> EffectOutcome:
        event(conn, self.jc.ctx, self.jc.job["id"], "effect_needs_operator", lease_token=self.jc.lease_token,
              detail={"reason": reason, "operation_key": key})
        return EffectOutcome(NeedsOperator(reason), None)

    def run(self, adapter: EffectAdapter, request: dict[str, Any],
            revalidate: Callable[[psycopg.Connection], str | None], *, key: str | None = None) -> EffectOutcome:
        jc, ctx = self.jc, self.jc.ctx
        key = key or operation_key(jc.job["id"], request)
        digest = hashlib.sha256(canonical(request).encode()).hexdigest()
        dedupe, lookup, fencing = capabilities(adapter)
        repeat_safe = dedupe != "none" or fencing
        # ---- 1: fenced checks, intent, restore detection
        with jc.db.tenant_tx(ctx) as conn:
            job = jc.fenced(conn)
            if job["cancel_requested"]:
                event(conn, ctx, job["id"], "effect_skipped_cancelled", lease_token=jc.lease_token)
                return EffectOutcome(Fail("cancelled before the effect"), None)
            denial = revalidate(conn)
            if denial:
                event(conn, ctx, job["id"], "effect_denied", lease_token=jc.lease_token, detail={"reason": denial})
                return EffectOutcome(Fail(f"denied before effect: {denial}"), None)
            fingerprint = conn.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]
            try:
                behind = witness_check(conn, self.witness)
            except WitnessUnavailable as exc:
                event(conn, ctx, job["id"], "effect_witness_unavailable", lease_token=jc.lease_token,
                      detail={"error": str(exc)})
                return EffectOutcome(Retry(f"restore witness unavailable, nothing sent: {exc}"), None)
            if behind:
                return self._park(conn, key, behind)
            intent = self._intent(conn, key)
            if intent is None:
                # ON CONFLICT: a concurrent job may create the same intent; we then wait for it and read it
                created = conn.execute(
                    """INSERT INTO axiom.effect_intents(tenant_id, id, job_id, integration, operation_key, request_digest,
                           lookup_supported, state, lease_token, db_fingerprint, dedupe, lookup, provider_fencing)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'prepared', %s, %s, %s, %s, %s)
                       ON CONFLICT (tenant_id, operation_key) DO NOTHING RETURNING id""",
                    (ctx.tenant_id, uuid.uuid4(), job["id"], adapter.integration, key, digest, lookup != "none",
                     jc.lease_token, fingerprint, dedupe, lookup, fencing)).fetchone()
                if created:
                    event(conn, ctx, job["id"], "intent_prepared", lease_token=jc.lease_token,
                          detail={"operation_key": key, "integration": adapter.integration, "dedupe": dedupe,
                                  "lookup": lookup, "provider_fencing": fencing})
                intent = self._intent(conn, key)
            if intent["request_digest"] != digest:
                return self._park(conn, key, "operation key reused with a different request")
            if intent["state"] in ("succeeded", "reconciled"):
                return EffectOutcome(Done({"external_ref": intent["external_ref"], "adopted": True}),
                                     intent["external_ref"], "recorded")
            if intent["state"] in ("failed", "abandoned"):
                return EffectOutcome(Fail(f"effect previously {intent['state']}"), None)
            restored = restore_doubt(conn, job, intent) is not None
            uncertain = restored or intent["state"] in ("executing", "unknown")
            if uncertain and lookup == "none" and not repeat_safe:
                return self._park(conn, key, (
                    "database restore detected (fingerprint changed, unacknowledged, or this job predates the latest "
                    "recovery acknowledgement); reconcile this job before its effect can run") if restored else
                    "previous attempt's outcome is unknown and the integration can neither be queried nor deduplicate")
        # ---- 2: lookup before create (a hit is proof; a miss is not)
        if lookup != "none":
            try:
                found = _find(adapter, key)
            except Exception as exc:  # noqa: BLE001 - cannot establish state: retry later, do not create
                return EffectOutcome(Retry(f"lookup failed: {type(exc).__name__}: {exc}"), None)
            if found:
                with jc.db.tenant_tx(ctx) as conn:
                    self._job_key_share(conn)
                    current = self._intent(conn, key)
                    if current["state"] not in ("succeeded", "reconciled"):
                        self._update(conn, current["id"], state="reconciled", external_ref=found,
                                     resolution="adopted by lookup")
                    event(conn, ctx, jc.job["id"], "effect_adopted", lease_token=jc.lease_token,
                          detail={"external_ref": found})
                return EffectOutcome(Done({"external_ref": found, "adopted": True}), found, "adopted_by_lookup")
        # ---- 3: mark executing under lock, re-reading state (closes the double-first-attempt race)
        with jc.db.tenant_tx(ctx) as conn:
            job = jc.fenced(conn)
            if job["cancel_requested"]:
                return EffectOutcome(Fail("cancelled before the effect"), None)
            denial = revalidate(conn)     # re-check at the effect boundary (A07)
            if denial:
                event(conn, ctx, job["id"], "effect_denied", lease_token=jc.lease_token, detail={"reason": denial})
                return EffectOutcome(Fail(f"denied before effect: {denial}"), None)
            current = self._intent(conn, key)
            if current["state"] in ("succeeded", "reconciled"):
                return EffectOutcome(Done({"external_ref": current["external_ref"], "adopted": True}),
                                     current["external_ref"], "recorded")
            if current["state"] in ("failed", "abandoned"):
                return EffectOutcome(Fail(f"effect previously {current['state']}"), None)
            if (uncertain or current["state"] != "prepared") and not repeat_safe:
                why = "lookup found nothing" if lookup != "none" else "the integration cannot be queried"
                return self._park(conn, key, (
                    f"an earlier attempt may have reached the provider and {why}; the provider cannot deduplicate, "
                    "so another create could duplicate the effect. Reconcile by hand"))
            watermark = conn.execute("SELECT nextval('axiom.effect_watermark_seq') AS n").fetchone()["n"]
            if self.witness is not None:
                # recorded outside the database before the request can be sent; a failure here rolls back
                # the transaction and nothing is sent
                self.witness.advance(watermark)
            self._update(conn, current["id"], state="executing", lease_token=jc.lease_token,
                         db_fingerprint=fingerprint, attempts=current["attempts"] + 1, effect_watermark=watermark)
            event(conn, ctx, job["id"], "effect_attempt", lease_token=jc.lease_token,
                  detail={"attempt": current["attempts"] + 1, "watermark": watermark,
                          "repeat": current["state"] != "prepared"})
        # ---- 4: the provider call (the unavoidable window: a lease lost from here on cannot stop this request)
        try:
            ref = adapter.create(key, request, jc.lease_token)
        except AlreadyExists as exc:
            self._record(key, "reconciled", exc.ref, None, resolution="provider reported the existing object")
            return EffectOutcome(Done({"external_ref": exc.ref, "adopted": True}), exc.ref, "adopted_by_lookup")
        except DefinitelyNotApplied as exc:
            self._record(key, "prepared", None, str(exc))
            return EffectOutcome(Retry(f"not applied: {exc}"), None)
        except PermanentFailure as exc:
            self._record(key, "failed", None, str(exc))
            return EffectOutcome(Fail(f"integration rejected the request: {exc}"), None)
        except Exception as exc:  # noqa: BLE001 - UnknownOutcome and anything unexpected after the call
            self._record(key, "unknown", None, f"{type(exc).__name__}: {exc}")
            if repeat_safe or lookup != "none":
                return EffectOutcome(Retry(f"outcome unknown, will reconcile: {exc}"), None)
            return EffectOutcome(NeedsOperator(f"outcome unknown and integration cannot be queried: {exc}"), None)
        self._record(key, "succeeded", ref, None)
        return EffectOutcome(Done({"external_ref": ref, "adopted": False}), ref, "created")

    def _record(self, key: str, state: str, ref: str | None, error: str | None, *, resolution: str | None = None
                ) -> None:
        """Record the observed outcome. Success is a fact about the external world and is written even if the lease
        was lost meanwhile; 'definitely not applied' only resets the intent if this attempt is still the latest."""
        jc = self.jc
        with jc.db.tenant_tx(jc.ctx) as conn:
            self._job_key_share(conn)
            intent = self._intent(conn, key)
            if intent["state"] in ("succeeded", "reconciled", "failed", "abandoned"):
                if ref and intent["external_ref"] != ref:
                    event(conn, jc.ctx, jc.job["id"], "effect_conflicting_outcome", lease_token=jc.lease_token,
                          detail={"recorded": intent["external_ref"], "observed": ref})
                return
            if state in ("prepared", "unknown") and intent["lease_token"] != jc.lease_token:
                event(conn, jc.ctx, jc.job["id"], f"effect_{state}_from_stale_attempt", lease_token=jc.lease_token,
                      detail={"error": error})
                if state == "prepared":
                    return
            fields: dict[str, Any] = {"state": state, "last_error": error}
            if ref:
                fields["external_ref"] = ref
            if resolution:
                fields["resolution"] = resolution
            self._update(conn, intent["id"], **fields)
            event(conn, jc.ctx, jc.job["id"], f"effect_{state}", lease_token=jc.lease_token,
                  detail={"external_ref": ref, "error": error})


__all__ = ["EffectGate", "EffectAdapter", "EffectOutcome", "DefinitelyNotApplied", "PermanentFailure",
           "UnknownOutcome", "AlreadyExists", "RestoreWitness", "operation_key", "StaleLease", "capabilities",
           "restore_doubt", "unaccounted_dispatches"]
