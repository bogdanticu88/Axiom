"""Ingestion pipeline: file imports and API syncs into observations, occurrences and cases.

Run lifecycle: queued -> running (leased, fencing token) -> completed | failed | cancelled.

* ``request_import`` validates permission, the original evidence (must be verified and readable by the
  requester) and the adapter, then queues a run. The original file is never modified.
* ``execute`` claims the run lease (incrementing the fencing token), re-verifies the original's digest,
  parses, and commits page by page. Each page commits atomically with every row derived from it and with
  its page marker; the page insert is fenced by the database against stale leases. Resuming skips pages
  already committed (same key and digest), so replays create no duplicates.
* ``finalise`` decides coverage from what the source said (complete / partial / unknown), records
  absence only for complete scans of identified deployments, and never closes a case.

This module is orchestration-agnostic: any engine (ADR 0006) can call ``execute(run_id)`` repeatedly;
the lease and fencing make concurrent or repeated calls safe.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .. import audit, outbox
from ..access import Authorizer
from ..adapters.base import (AssetRecord, FindingRecord, Identifier, ParseError, Parser, Quarantine, ScanSummary,
                             SubjectHints, identifier_strength, stable_digest)
from ..adapters.catalogue import parser as get_parser
from ..db import Database, TenantContext
from ..domains.cases.service import CaseService
from ..domains.evidence.objectstore import ObjectStore, TenantObjectStore
from ..errors import Conflict, NotFound, ValidationFailed
from . import identity

log = logging.getLogger(__name__)

PAGE_SIZE = 200
LEASE_SECONDS = 300
READ_PERMISSION = {"internal": "evidence.read:internal", "confidential": "evidence.read:confidential",
                   "restricted": "evidence.read:restricted"}


class LeaseLost(Conflict):
    code = "lease_lost"


@dataclass
class RunState:
    run: dict
    lease_token: int
    worker_id: str
    counts: dict[str, int] = field(default_factory=lambda: {
        "findings": 0, "assets": 0, "quarantined": 0, "occurrences_new": 0, "cases_created": 0,
        "cases_linked": 0, "cases_reopened": 0, "identity_candidates": 0, "non_findings": 0,
        "pages_committed": 0, "pages_skipped": 0})
    summaries: list[ScanSummary] = field(default_factory=list)
    asset_versions: set[UUID] = field(default_factory=set)


def parse_declared_subject(raw: dict | None) -> SubjectHints | None:
    if raw is None:
        return None
    try:
        idents = tuple(Identifier(i["namespace"], str(i["value"])) for i in raw.get("identifiers", []))
        for i in idents:
            identifier_strength(i.namespace)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationFailed(f"invalid declared subject: {exc}") from exc
    if not any(i.strength == "strong" for i in idents):
        raise ValidationFailed("a declared subject needs at least one strong identifier")
    kind = raw.get("kind", "unknown")
    if kind not in {"host", "container_image", "workload", "cloud_resource", "repository", "application", "unknown"}:
        raise ValidationFailed("invalid asset kind")
    return SubjectHints(identifiers=idents, kind=kind, display_name=str(raw.get("display_name") or idents[0].value),
                        deployment_digest=raw.get("deployment_digest"), version_label=raw.get("version_label"),
                        declared=True)


class IngestionService:
    def __init__(self, db: Database, store: ObjectStore, *, page_size: int = PAGE_SIZE,
                 lease_seconds: int = LEASE_SECONDS):
        self.db = db
        self.store = store
        self.page_size = page_size
        self.lease_seconds = lease_seconds

    # ------------------------------------------------------------------ requests and queries
    def request_import(self, ctx: TenantContext, *, evidence_id: UUID, adapter: str, scope_id: UUID,
                       declared_subject: dict | None = None) -> dict:
        try:
            p = get_parser(adapter)
        except KeyError as exc:
            raise ValidationFailed(str(exc)) from exc
        if "file_import" not in p.info.operations:
            raise ValidationFailed(f"adapter {adapter} does not support file imports")
        subject = parse_declared_subject(declared_subject)
        with self.db.tenant_tx(ctx) as conn:
            authz = Authorizer(conn, ctx)
            authority = authz.require("ingestion.import", scope_id)
            ev = conn.execute("SELECT * FROM axiom.evidence_objects WHERE id = %s", (evidence_id,)).fetchone()
            if ev is None:
                raise NotFound("evidence not found", code="evidence_not_found")
            authz.require(READ_PERMISSION[ev["classification"]], ev["scope_id"])
            if ev["status"] != "verified":
                raise Conflict("only verified evidence can be imported", code="evidence_not_verified")
            run_id = uuid.uuid4()
            row = conn.execute(
                """INSERT INTO axiom.ingestion_runs(tenant_id, id, scope_id, source_kind, adapter, adapter_version,
                       raw_evidence_id, declared_subject, status, requested_by)
                   VALUES (%s, %s, %s, 'file_import', %s, %s, %s, %s, 'queued', %s) RETURNING *""",
                (ctx.tenant_id, run_id, scope_id, adapter, p.info.version, evidence_id,
                 Jsonb(declared_subject) if subject else None, ctx.principal_id)).fetchone()
            audit.record(conn, ctx, action="ingestion.import_requested", resource_type="ingestion_run",
                         resource_id=run_id, detail={"adapter": adapter, "evidence_id": str(evidence_id),
                                                     "declared_subject": subject is not None,
                                                     "authority": authority.as_json()})
            outbox.enqueue(conn, ctx, topic="ingestion.run_requested", aggregate_type="ingestion_run",
                           aggregate_id=run_id, payload={"run_id": str(run_id)})
            from .jobs import enqueue_run   # local import: jobs imports this module
            enqueue_run(conn, ctx, run_id)
            return row

    def get_run(self, ctx: TenantContext, run_id: UUID) -> dict:
        with self.db.tenant_tx(ctx) as conn:
            run = conn.execute("SELECT * FROM axiom.ingestion_runs WHERE id = %s", (run_id,)).fetchone()
            if run is None:
                raise NotFound("ingestion run not found", code="run_not_found")
            Authorizer(conn, ctx).require("ingestion.read", run["scope_id"])
            run = dict(run)
            run["quarantined"] = list(conn.execute(
                "SELECT raw_locator, reason_code, detail, record_digest FROM axiom.quarantined_records "
                "WHERE run_id = %s ORDER BY raw_locator LIMIT 1000", (run_id,)))
            return run

    # --------------------------------------------------------------------------- execution
    def execute(self, tenant_id: UUID, system_principal_id: UUID, run_id: UUID, *, worker_id: str,
                on_page_committed: Callable[[int], None] | None = None) -> dict | None:
        """Claim and run (or resume) one run as the tenant's system principal. Returns the final run row,
        or None if another worker holds a live lease."""
        ctx = TenantContext(tenant_id, system_principal_id, "workload", f"ingestion:{run_id}")
        state = self._claim(ctx, run_id, worker_id)
        if state is None:
            return None
        run = state.run
        try:
            data = self._load_original(ctx, run)
            parser = get_parser(run["adapter"])
            declared = parse_declared_subject(run["declared_subject"]) if run["declared_subject"] else None
            events = list(parser.parse(data, declared_subject=declared))
        except (ParseError, ValidationFailed) as exc:
            return self._fail(ctx, state, f"{type(exc).__name__}: {exc}")
        records = [e for e in events if not isinstance(e, ScanSummary)]
        state.summaries = [e for e in events if isinstance(e, ScanSummary)]
        for index, page in enumerate(_pages(records, self.page_size)):
            key = f"file:{index}"
            digest = stable_digest([[getattr(e, "locator", ""), stable_digest(getattr(e, "source_fields", None) or
                                                                              getattr(e, "detail", ""))] for e in page])
            self._commit_page(ctx, state, key, digest, page, raw_evidence_id=run["raw_evidence_id"])
            if on_page_committed:
                on_page_committed(index)
        return self._finalise(ctx, state)

    def _claim(self, ctx: TenantContext, run_id: UUID, worker_id: str) -> RunState | None:
        with self.db.tenant_tx(ctx) as conn:
            authz = Authorizer(conn, ctx)
            run = conn.execute(
                """UPDATE axiom.ingestion_runs SET status = 'running', lease_owner = %s, lease_token = lease_token + 1,
                          lease_expires_at = clock_timestamp() + make_interval(secs => %s), attempts = attempts + 1,
                          started_at = COALESCE(started_at, clock_timestamp()), record_version = record_version + 1
                    WHERE id = %s AND status IN ('queued', 'running')
                      AND (lease_expires_at IS NULL OR lease_expires_at < clock_timestamp())
                RETURNING *""", (worker_id, self.lease_seconds, run_id)).fetchone()
            if run is None:
                exists = conn.execute("SELECT status FROM axiom.ingestion_runs WHERE id = %s", (run_id,)).fetchone()
                if exists is None:
                    raise NotFound("ingestion run not found", code="run_not_found")
                return None
            # The worker's authority is its explicit role binding, checked for every claim.
            authz.require("asset.manage", run["scope_id"])
            authz.require("case.create", run["scope_id"])
            audit.record(conn, ctx, action="ingestion.run_claimed", resource_type="ingestion_run", resource_id=run_id,
                         detail={"worker": worker_id, "lease_token": run["lease_token"], "attempt": run["attempts"]})
        state = RunState(run, run["lease_token"], worker_id)
        # Restore counters from earlier attempts so resumed runs report totals.
        state.counts.update({k: v for k, v in (run["counts"] or {}).items() if k in state.counts})
        return state

    def _load_original(self, ctx: TenantContext, run: dict) -> bytes:
        with self.db.tenant_tx(ctx) as conn:
            ev = conn.execute("SELECT * FROM axiom.evidence_objects WHERE id = %s", (run["raw_evidence_id"],)).fetchone()
        data = b"".join(TenantObjectStore(self.store, ctx.tenant_id).get(ev["object_key"]))
        if hashlib.sha256(data).hexdigest() != ev["observed_digest"] or len(data) != ev["observed_size"]:
            raise ValidationFailed("original evidence no longer matches its verified digest")
        return data

    def _commit_page(self, ctx: TenantContext, state: RunState, key: str, digest: str, page: Sequence[Any], *,
                     raw_evidence_id: UUID, page_evidence_id: UUID | None = None) -> bool:
        """Commit one page atomically. Returns False when the page was already committed."""
        with self.db.tenant_tx(ctx) as conn:
            existing = conn.execute("SELECT page_digest FROM axiom.ingestion_pages WHERE run_id = %s AND page_key = %s",
                                    (state.run["id"], key)).fetchone()
            if existing:
                if existing["page_digest"] != digest:
                    raise Conflict("source content changed between attempts", code="page_digest_mismatch")
                state.counts["pages_skipped"] += 1
                return False
            authz = Authorizer(conn, ctx)
            cases = CaseService(conn, ctx, authz)
            page_counts = {k: 0 for k in state.counts}
            for event in page:
                if isinstance(event, Quarantine):
                    conn.execute(
                        """INSERT INTO axiom.quarantined_records(tenant_id, id, run_id, raw_evidence_id, raw_locator,
                               reason_code, detail, record_digest) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT DO NOTHING""",
                        (ctx.tenant_id, uuid.uuid4(), state.run["id"], raw_evidence_id, event.locator,
                         event.reason_code, event.detail[:2000], event.record_digest))
                    page_counts["quarantined"] += 1
                elif isinstance(event, FindingRecord):
                    self._finding(conn, ctx, cases, state, event, raw_evidence_id, page_counts)
                elif isinstance(event, AssetRecord):
                    self._asset(conn, ctx, state, event, raw_evidence_id, page_counts)
            page_counts["pages_committed"] = 1
            for k, v in page_counts.items():
                state.counts[k] += v
            # Fenced: the trigger refuses the page unless this lease token is still current.
            conn.execute(
                """INSERT INTO axiom.ingestion_pages(tenant_id, run_id, page_key, page_digest, evidence_id, record_count,
                       lease_token) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (ctx.tenant_id, state.run["id"], key, digest, page_evidence_id, len(page), state.lease_token))
            updated = conn.execute(
                """UPDATE axiom.ingestion_runs SET counts = %s, record_version = record_version + 1,
                          lease_expires_at = clock_timestamp() + make_interval(secs => %s)
                    WHERE id = %s AND lease_token = %s AND status = 'running' RETURNING id""",
                (Jsonb(state.counts), self.lease_seconds, state.run["id"], state.lease_token)).fetchone()
            if updated is None:
                raise LeaseLost("ingestion lease lost")
            audit.record(conn, ctx, action="ingestion.page_committed", resource_type="ingestion_run",
                         resource_id=state.run["id"], detail={"page": key, "records": len(page),
                                                              **{k: v for k, v in page_counts.items() if v}})
        return True

    def _source_record(self, conn, ctx, state: RunState, record_type: str, external_id: str, version_key: str) -> UUID:
        namespace = state.run["adapter"] if state.run["connection_id"] is None else \
            f"{state.run['adapter']}:{state.run['connection_id']}"
        row = conn.execute(
            """INSERT INTO axiom.source_records(tenant_id, id, source_namespace, record_type, external_id, version_key,
                   first_run_id) VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id, source_namespace, record_type, external_id, version_key) DO NOTHING
               RETURNING id""",
            (ctx.tenant_id, uuid.uuid4(), namespace, record_type, external_id[:2000], version_key,
             state.run["id"])).fetchone()
        if row:
            return row["id"]
        return conn.execute(
            """SELECT id FROM axiom.source_records WHERE source_namespace = %s AND record_type = %s AND external_id = %s
                 AND version_key = %s""", (namespace, record_type, external_id[:2000], version_key)).fetchone()["id"]

    def _observation(self, conn, ctx, state, source_record_id, raw_evidence_id, locator, otype, asset_id, version_id,
                     source_time, normalised, source_fields) -> UUID | None:
        obs_id = uuid.uuid4()
        collected = datetime.now(timezone.utc)
        row = conn.execute(
            """INSERT INTO axiom.observations(tenant_id, id, run_id, source_record_id, raw_evidence_id, raw_locator,
                   observation_type, subject_asset_id, subject_asset_version_id, source_time, collected_at,
                   normalised, source_fields, observation_digest)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id, run_id, source_record_id) DO NOTHING RETURNING id""",
            (ctx.tenant_id, obs_id, state.run["id"], source_record_id, raw_evidence_id, locator, otype, asset_id,
             version_id, source_time, collected, Jsonb(normalised), Jsonb(source_fields),
             stable_digest(source_fields))).fetchone()
        return row["id"] if row else None

    def _resolve(self, conn, ctx, state, subject: SubjectHints, page_counts) -> identity.Resolution:
        resolution = identity.resolve(conn, ctx, subject, state.run["scope_id"])
        return resolution

    def _finding(self, conn, ctx, cases: CaseService, state: RunState, rec: FindingRecord, raw_evidence_id,
                 page_counts) -> None:
        resolution = self._resolve(conn, ctx, state, rec.subject, page_counts)
        observed_at = rec.source_time or datetime.now(timezone.utc)
        version_id = identity.asset_version(conn, ctx, resolution.asset_id, rec.subject, observed_at)
        state.asset_versions.add(version_id)
        source_id = self._source_record(conn, ctx, state, "finding", rec.external_id, rec.version_key)
        otype = {"open": "finding_reported", "fixed": "finding_fixed_by_source",
                 "suppressed": "finding_suppressed_by_source"}[rec.source_status]
        obs_id = self._observation(conn, ctx, state, source_id, raw_evidence_id, rec.locator, otype,
                                   resolution.asset_id, version_id, rec.source_time, rec.normalised, rec.source_fields)
        identity.record_identifiers(conn, ctx, resolution, observation_id=obs_id, declared=rec.subject.declared)
        page_counts["identity_candidates"] += identity.record_candidates(conn, ctx, resolution,
                                                                         run_id=state.run["id"], observation_id=obs_id)
        page_counts["findings"] += 1
        occ = conn.execute(
            """INSERT INTO axiom.finding_occurrences(tenant_id, id, source_system, source_finding_id, asset_version_id,
                   component_locator, vulnerability_ref, title, source_severity, first_run_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id, source_system, source_finding_id, asset_version_id, component_locator)
               DO NOTHING RETURNING *""",
            (ctx.tenant_id, uuid.uuid4(), state.run["adapter"], rec.external_id[:2000], version_id,
             rec.component_locator, rec.vulnerability_ref, (rec.title or "")[:500] or None, rec.source_severity,
             state.run["id"])).fetchone()
        new = occ is not None
        if not new:
            occ = conn.execute(
                """SELECT * FROM axiom.finding_occurrences WHERE source_system = %s AND source_finding_id = %s
                     AND asset_version_id = %s AND component_locator = %s""",
                (state.run["adapter"], rec.external_id[:2000], version_id, rec.component_locator)).fetchone()
        else:
            page_counts["occurrences_new"] += 1
        status = {"open": "present", "fixed": "fixed_by_source", "suppressed": "suppressed_by_source"}[rec.source_status]
        conn.execute(
            """INSERT INTO axiom.occurrence_observations(tenant_id, occurrence_id, run_id, observation_id, observed_status,
                   source_time) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
            (ctx.tenant_id, occ["id"], state.run["id"], obs_id, status, rec.source_time))
        self._correlate(conn, cases, state, occ, resolution.asset_id, rec, new, page_counts)

    def _correlate(self, conn, cases: CaseService, state: RunState, occ: dict, asset_id: UUID, rec: FindingRecord,
                   new: bool, page_counts) -> None:
        """Attach occurrences to cases. Source-reported fixes never close or create cases."""
        linked = conn.execute(
            """SELECT c.* FROM axiom.case_occurrence_links l JOIN axiom.finding_cases c ON c.id = l.case_id
                WHERE l.occurrence_id = %s AND l.unlinked_at IS NULL""", (occ["id"],)).fetchall()
        if rec.source_status == "fixed":
            return
        if linked:
            # Seen again after a verified closure: the reported fix does not hold for this deployment.
            for case in linked:
                if case["workflow"] == "closed":
                    closure = conn.execute(
                        "SELECT * FROM axiom.closure_records WHERE case_id = %s AND case_event_sequence = %s",
                        (case["id"], case["record_version"])).fetchone()
                    if closure and closure["reason"] == "verified_remediated":
                        cases.reopen(case["id"], case["record_version"], reason="recurrence", system=True,
                                     rationale=f"occurrence {occ['id']} observed again in run {state.run['id']} "
                                               "after verified closure")
                        page_counts["cases_reopened"] += 1
            return
        match = None
        if occ["vulnerability_ref"]:
            match = conn.execute(
                """SELECT c.* FROM axiom.finding_cases c
                     JOIN axiom.case_occurrence_links l ON l.case_id = c.id AND l.unlinked_at IS NULL
                     JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
                     JOIN axiom.asset_versions v ON v.id = o.asset_version_id
                    WHERE v.asset_id = %s AND o.vulnerability_ref = %s AND o.source_system = %s
                    ORDER BY (c.workflow = 'closed'), c.updated_at DESC LIMIT 1""",
                (asset_id, occ["vulnerability_ref"], occ["source_system"])).fetchone()
        if match is None:
            title = f"{occ['vulnerability_ref'] or 'finding'}: {(occ['title'] or occ['component_locator'])[:300]}"
            cases.create(scope_id=state.run["scope_id"], title=title[:500], occurrence_ids=[occ["id"]])
            page_counts["cases_created"] += 1
            return
        version = match["record_version"]
        if match["workflow"] == "closed":
            reopened = cases.reopen(match["id"], version, reason="recurrence", system=True,
                                    rationale=f"new occurrence {occ['id']} in run {state.run['id']}")
            version = reopened["record_version"]
            page_counts["cases_reopened"] += 1
        cases.link_occurrence(match["id"], version, occ["id"], f"correlated by ingestion run {state.run['id']}")
        page_counts["cases_linked"] += 1

    def _asset(self, conn, ctx, state: RunState, rec: AssetRecord, raw_evidence_id, page_counts) -> None:
        resolution = self._resolve(conn, ctx, state, rec.subject, page_counts)
        source_id = self._source_record(conn, ctx, state, "asset", rec.external_id, rec.version_key)
        obs_id = self._observation(conn, ctx, state, source_id, raw_evidence_id, rec.locator, "asset_context",
                                   resolution.asset_id, None, rec.source_time, rec.context, rec.source_fields)
        identity.record_identifiers(conn, ctx, resolution, observation_id=obs_id, declared=False)
        page_counts["identity_candidates"] += identity.record_candidates(conn, ctx, resolution,
                                                                         run_id=state.run["id"], observation_id=obs_id)
        page_counts["assets"] += 1
        current = conn.execute(
            """SELECT owner_ref, criticality, environment FROM axiom.business_context_versions WHERE asset_id = %s
                ORDER BY effective_from DESC, recorded_at DESC LIMIT 1""", (resolution.asset_id,)).fetchone()
        proposed = {"owner_ref": rec.context.get("owner_ref"), "criticality": rec.context.get("criticality"),
                    "environment": rec.context.get("environment")}
        if obs_id and any(proposed.values()) and (current is None or dict(current) != proposed):
            conn.execute(
                """INSERT INTO axiom.business_context_versions(tenant_id, id, asset_id, owner_ref, criticality,
                       environment, basis, source_observation_id, effective_from)
                   VALUES (%s, %s, %s, %s, %s, %s, 'source_tag_assertion', %s, clock_timestamp())""",
                (ctx.tenant_id, uuid.uuid4(), resolution.asset_id, proposed["owner_ref"], proposed["criticality"],
                 proposed["environment"], obs_id))

    def _finalise(self, ctx: TenantContext, state: RunState, *, extra_reason: str | None = None,
                  source_complete: bool | None = None,
                  checkpoint: tuple[UUID, str, dict] | None = None) -> dict:
        """Complete the run. ``source_complete`` (API syncs) states whether the source delivered everything it
        was asked for; for file imports completeness comes from the parsed documents. ``checkpoint`` is
        (connection_id, stream, cursor) and is advanced in the same transaction, only for complete runs."""
        state.counts["non_findings"] = sum(s.non_findings for s in state.summaries)
        quarantined = state.counts["quarantined"]
        stated = [source_complete] if source_complete is not None else [s.complete for s in state.summaries]
        if any(c is False for c in stated) or quarantined:
            coverage = "partial"
        elif stated and all(c is True for c in stated):
            coverage = "complete"
        else:
            coverage = "unknown"
        reasons = [s.completeness_reason for s in state.summaries]
        if quarantined:
            reasons.append(f"{quarantined} record(s) quarantined")
        if extra_reason:
            reasons.append(extra_reason)
        absent = 0
        with self.db.tenant_tx(ctx) as conn:
            infer = coverage == "complete" and state.summaries and all(s.supports_absence_inference
                                                                       for s in state.summaries)
            versions = [r["v"] for r in conn.execute(
                "SELECT DISTINCT subject_asset_version_id AS v FROM axiom.observations WHERE run_id = %s "
                "AND subject_asset_version_id IS NOT NULL", (state.run["id"],))]
            if infer and versions:
                rows = conn.execute(
                    """INSERT INTO axiom.occurrence_observations(tenant_id, occurrence_id, run_id, observed_status)
                       SELECT o.tenant_id, o.id, %s, 'absent_in_complete_scan' FROM axiom.finding_occurrences o
                        WHERE o.asset_version_id = ANY(%s) AND o.source_system = %s
                          AND NOT EXISTS (SELECT 1 FROM axiom.occurrence_observations x
                                           WHERE x.occurrence_id = o.id AND x.run_id = %s)
                          AND EXISTS (SELECT 1 FROM axiom.occurrence_observations p
                                       WHERE p.occurrence_id = o.id AND p.observed_status = 'present')
                       RETURNING occurrence_id""",
                    (state.run["id"], versions, state.run["adapter"], state.run["id"])).fetchall()
                absent = len(rows)
            state.counts["absent_in_complete_scan"] = absent
            if checkpoint and coverage == "complete":
                connection_id, stream, cursor = checkpoint
                conn.execute(
                    """INSERT INTO axiom.connection_checkpoints(tenant_id, connection_id, stream, cursor, last_durable_run_id)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (tenant_id, connection_id, stream) DO UPDATE
                         SET cursor = EXCLUDED.cursor, last_durable_run_id = EXCLUDED.last_durable_run_id,
                             updated_at = clock_timestamp(),
                             record_version = axiom.connection_checkpoints.record_version + 1""",
                    (ctx.tenant_id, connection_id, stream, Jsonb(cursor), state.run["id"]))
            row = conn.execute(
                """UPDATE axiom.ingestion_runs SET status = 'completed', coverage = %s, coverage_reason = %s, counts = %s,
                          finished_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL,
                          record_version = record_version + 1
                    WHERE id = %s AND lease_token = %s AND status = 'running' RETURNING *""",
                (coverage, "; ".join(reasons)[:2000], Jsonb(state.counts), state.run["id"],
                 state.lease_token)).fetchone()
            if row is None:
                raise LeaseLost("ingestion lease lost before finalisation")
            audit.record(conn, ctx, action="ingestion.run_completed", resource_type="ingestion_run",
                         resource_id=state.run["id"], detail={"coverage": coverage, "counts": state.counts})
            outbox.enqueue(conn, ctx, topic="ingestion.run_completed", aggregate_type="ingestion_run",
                           aggregate_id=state.run["id"], payload={"coverage": coverage, "counts": state.counts})
            return row

    def _fail(self, ctx: TenantContext, state: RunState, error: str) -> dict:
        with self.db.tenant_tx(ctx) as conn:
            row = conn.execute(
                """UPDATE axiom.ingestion_runs SET status = 'failed', coverage = 'failed', error_summary = %s,
                          counts = %s, finished_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL,
                          record_version = record_version + 1
                    WHERE id = %s AND lease_token = %s AND status = 'running' RETURNING *""",
                (error[:2000], Jsonb(state.counts), state.run["id"], state.lease_token)).fetchone()
            if row is None:
                raise LeaseLost("ingestion lease lost before failure could be recorded")
            audit.record(conn, ctx, action="ingestion.run_failed", resource_type="ingestion_run",
                         resource_id=state.run["id"], outcome="failed", reason_code="parse_error",
                         detail={"error": error[:500]})
            return row


def _pages(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]
