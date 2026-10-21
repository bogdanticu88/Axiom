"""Effect gate: the only way a job step may cause an external effect (Plan 7, B07, B08, ADR 0006).

Protocol for one effect identified by a stable ``operation_key`` (derived from the job and the exact request):

1. Fenced check: the worker still holds the lease, the job is not cancelled, and ``revalidate`` (approval,
   permission, resource preconditions) still passes, all in one transaction with the intent row.
2. Intent: create or load the intent for the operation key. Terminal intents return their recorded outcome.
3. Restore detection: an intent written under a different database fingerprint, or a fingerprint nobody has
   acknowledged, means the database was restored. Integrations without reliable lookup then need an operator.
4. Lookup before create (every attempt, not only after failures) when the integration supports it, so effects
   performed after a backup was taken are adopted rather than repeated.
5. Mark executing (fenced), call the integration with the operation key as idempotency key and the lease token
   as fencing token, then record succeeded / failed / unknown / definitely-not-applied.

No exactly-once claim: this records intent and reconciles; integrations that can neither deduplicate nor be
queried end in ``needs_operator`` instead of being retried blindly.
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


class DefinitelyNotApplied(Exception):
    """The integration guarantees the request had no effect (e.g. rejected before processing). Safe to retry."""


class PermanentFailure(Exception):
    """The integration rejected the request; retrying the same request will not help."""


class UnknownOutcome(Exception):
    """The request may or may not have taken effect (timeout after send, connection reset, ambiguous 5xx)."""


class EffectAdapter(Protocol):
    integration: str
    lookup_supported: bool

    def lookup(self, operation_key: str) -> str | None: ...

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str: ...


def operation_key(job_id, request: dict[str, Any]) -> str:
    return hashlib.sha256(f"{job_id}|{canonical(request)}".encode()).hexdigest()


def canonical(request: dict[str, Any]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class EffectOutcome:
    step: StepResult
    external_ref: str | None


class EffectGate:
    def __init__(self, jc: JobContext):
        self.jc = jc

    def _intent(self, conn: psycopg.Connection, key: str) -> dict | None:
        return conn.execute("SELECT * FROM axiom.effect_intents WHERE operation_key = %s FOR UPDATE", (key,)).fetchone()

    def _update(self, conn, intent_id, **fields) -> None:
        sets = ", ".join(f"{k} = %({k})s" for k in fields)
        conn.execute(f"UPDATE axiom.effect_intents SET {sets}, updated_at = clock_timestamp(), "
                     f"record_version = record_version + 1 WHERE id = %(id)s", {**fields, "id": intent_id})

    def run(self, adapter: EffectAdapter, request: dict[str, Any],
            revalidate: Callable[[psycopg.Connection], str | None]) -> EffectOutcome:
        jc, ctx = self.jc, self.jc.ctx
        key = operation_key(jc.job["id"], request)
        digest = hashlib.sha256(canonical(request).encode()).hexdigest()
        # 1-3: fenced checks, intent, restore detection
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
            acknowledged = conn.execute("SELECT 1 FROM axiom.recovery_acknowledgements WHERE fingerprint = %s",
                                        (fingerprint,)).fetchone() is not None
            intent = self._intent(conn, key)
            if intent is None:
                intent_id = uuid.uuid4()
                conn.execute(
                    """INSERT INTO axiom.effect_intents(tenant_id, id, job_id, integration, operation_key, request_digest,
                           lookup_supported, state, lease_token, db_fingerprint)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'prepared', %s, %s)""",
                    (ctx.tenant_id, intent_id, job["id"], adapter.integration, key, digest, adapter.lookup_supported,
                     jc.lease_token, fingerprint))
                intent = {"id": intent_id, "state": "prepared", "db_fingerprint": fingerprint, "external_ref": None}
                event(conn, ctx, job["id"], "intent_prepared", lease_token=jc.lease_token,
                      detail={"operation_key": key, "integration": adapter.integration})
            if intent["state"] in ("succeeded", "reconciled"):
                return EffectOutcome(Done({"external_ref": intent["external_ref"], "adopted": True}),
                                     intent["external_ref"])
            if intent["state"] in ("failed", "abandoned"):
                return EffectOutcome(Fail(f"effect previously {intent['state']}"), None)
            restored = (intent["db_fingerprint"] != fingerprint or job["db_fingerprint"] != fingerprint
                        or not acknowledged)
            uncertain = intent["state"] in ("executing", "unknown")
            if not adapter.lookup_supported and (restored or uncertain):
                reason = ("database restore detected (fingerprint changed or unacknowledged); reconcile and "
                          "acknowledge before effects on integrations without lookup") if restored else \
                         "previous attempt's outcome is unknown and the integration cannot be queried"
                event(conn, ctx, job["id"], "effect_needs_operator", lease_token=jc.lease_token,
                      detail={"reason": reason, "operation_key": key})
                return EffectOutcome(NeedsOperator(reason), None)
        # 4: lookup before create
        if adapter.lookup_supported:
            try:
                found = adapter.lookup(key)
            except Exception as exc:  # noqa: BLE001 - cannot establish state: retry later, do not create
                return EffectOutcome(Retry(f"lookup failed: {type(exc).__name__}: {exc}"), None)
            if found:
                with jc.db.tenant_tx(ctx) as conn:
                    current = self._intent(conn, key)
                    if current["state"] not in ("succeeded", "reconciled"):
                        self._update(conn, current["id"], state="reconciled", external_ref=found,
                                     resolution="adopted by lookup")
                    event(conn, ctx, jc.job["id"], "effect_adopted", lease_token=jc.lease_token,
                          detail={"external_ref": found})
                return EffectOutcome(Done({"external_ref": found, "adopted": True}), found)
        # 5: execute
        with jc.db.tenant_tx(ctx) as conn:
            job = jc.fenced(conn)
            if job["cancel_requested"]:
                return EffectOutcome(Fail("cancelled before the effect"), None)
            denial = revalidate(conn)     # re-check at the effect boundary (A07)
            if denial:
                return EffectOutcome(Fail(f"denied before effect: {denial}"), None)
            current = self._intent(conn, key)
            self._update(conn, current["id"], state="executing", lease_token=jc.lease_token,
                         db_fingerprint=fingerprint, attempts=current.get("attempts", 0) + 1)
        try:
            ref = adapter.create(key, request, jc.lease_token)
        except DefinitelyNotApplied as exc:
            self._record(key, "prepared", None, str(exc))
            return EffectOutcome(Retry(f"not applied: {exc}"), None)
        except PermanentFailure as exc:
            self._record(key, "failed", None, str(exc))
            return EffectOutcome(Fail(f"integration rejected the request: {exc}"), None)
        except Exception as exc:  # noqa: BLE001 - UnknownOutcome and anything unexpected after the call
            self._record(key, "unknown", None, f"{type(exc).__name__}: {exc}")
            if adapter.lookup_supported:
                return EffectOutcome(Retry(f"outcome unknown, will reconcile by lookup: {exc}"), None)
            return EffectOutcome(NeedsOperator(f"outcome unknown and integration cannot be queried: {exc}"), None)
        self._record(key, "succeeded", ref, None)
        return EffectOutcome(Done({"external_ref": ref, "adopted": False}), ref)

    def _record(self, key: str, state: str, ref: str | None, error: str | None) -> None:
        """Record the observed outcome. This is a fact about the external world, so it is written even if the
        lease was lost meanwhile; the job's own state transition stays fenced in the worker."""
        jc = self.jc
        with jc.db.tenant_tx(jc.ctx) as conn:
            intent = self._intent(conn, key)
            if intent["state"] in ("succeeded", "reconciled", "failed", "abandoned"):
                return
            fields: dict[str, Any] = {"state": state, "last_error": error}
            if ref:
                fields["external_ref"] = ref
            self._update(conn, intent["id"], **fields)
            event(conn, jc.ctx, jc.job["id"], f"effect_{state}", lease_token=jc.lease_token,
                  detail={"external_ref": ref, "error": error})


__all__ = ["EffectGate", "EffectAdapter", "EffectOutcome", "DefinitelyNotApplied", "PermanentFailure",
           "UnknownOutcome", "operation_key", "StaleLease"]
