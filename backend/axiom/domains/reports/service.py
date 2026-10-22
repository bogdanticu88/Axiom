"""Report snapshots, exports and auditor evidence packages (RPT-01, 02, 05, 06; RISK-04).

Snapshots (``exposure_summary@2``) are reproducible as of a time: every figure comes from append-only history
filtered by ``as_of``, never from mutable current-state columns, so regenerating a snapshot for the same ``as_of``
yields the same content and digest. Cases, occurrences and assets have separate denominators. Coverage is reported
per source, and a successful synchronisation is not treated as complete coverage. Unknowns (unprioritised or
unassessed cases, unresolved owners, inconclusive results, partial or stale coverage) are counted explicitly, and
accepted risk, dismissals, duplicates and retirements are counted apart from verified remediation.

Evidence packages are per case. Evidence content is included only where the requester may read its classification;
other objects are listed by reference and digest with the reason they are withheld. Every package and export read is
audited and digest-checked.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import uuid
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, NotFound, ValidationFailed
from ..evidence.objectstore import TenantObjectStore

QUERY_VERSION = "exposure_summary@4"
MAX_EXPORT_BYTES = 50 * 1024 * 1024
MAX_INLINE_EVIDENCE = 1024 * 1024
READ_PERMISSION = {"public": None, "internal": "evidence.read:internal", "confidential": "evidence.read:confidential",
                   "restricted": "evidence.read:restricted"}
META_PERMISSION = {"public": None, "internal": "evidence.metadata:internal",
                   "confidential": "evidence.metadata:confidential", "restricted": "evidence.metadata:restricted"}
STATEMENTS = [
    "A successful synchronisation does not prove complete coverage: completeness is reported per source separately.",
    "Accepted risk, dismissal, duplicate and retired-asset closures are not verified remediation.",
    "Unprioritised and unassessed cases, and inconclusive results, are counted explicitly rather than omitted.",
    "Figures are reconstructed from append-only history as of the stated time.",
]

_SQL = """
WITH RECURSIVE tree(id) AS (SELECT %(scope)s::uuid UNION ALL SELECT s.id FROM axiom.scopes s JOIN tree ON s.parent_id = tree.id),
cases AS (SELECT id, created_at FROM axiom.finding_cases WHERE scope_id IN (SELECT id FROM tree) AND created_at <= %(t)s),
last_event AS (SELECT DISTINCT ON (e.case_id) e.case_id, e.to_workflow, e.event_type, e.sequence
                 FROM axiom.case_events e JOIN cases c ON c.id = e.case_id WHERE e.created_at <= %(t)s
                ORDER BY e.case_id, e.sequence DESC),
prio AS (SELECT DISTINCT ON (e.case_id) e.case_id, e.payload->>'priority_to' AS priority
           FROM axiom.case_events e JOIN cases c ON c.id = e.case_id
          WHERE e.created_at <= %(t)s AND e.event_type IN ('case.prioritised', 'case.priority_overridden')
          ORDER BY e.case_id, e.sequence DESC),
assess AS (SELECT DISTINCT ON (d.case_id) d.case_id, d.outcome FROM axiom.decisions d JOIN cases c ON c.id = d.case_id
            WHERE d.kind = 'assessment' AND d.recorded_at <= %(t)s ORDER BY d.case_id, d.recorded_at DESC, d.id DESC),
verif AS (SELECT DISTINCT ON (v.case_id) v.case_id, v.outcome FROM axiom.verification_runs v JOIN cases c ON c.id = v.case_id
           WHERE v.recorded_at <= %(t)s ORDER BY v.case_id, v.recorded_at DESC, v.id DESC),
st AS (SELECT c.id, le.to_workflow AS workflow, COALESCE(p.priority, 'pending') AS priority, a.outcome AS assessment,
              v.outcome AS verification, le.sequence
         FROM cases c JOIN last_event le ON le.case_id = c.id LEFT JOIN prio p ON p.case_id = c.id
         LEFT JOIN assess a ON a.case_id = c.id LEFT JOIN verif v ON v.case_id = c.id),
closures AS (SELECT cr.reason FROM axiom.closure_records cr JOIN st ON st.id = cr.case_id
              WHERE st.workflow = 'closed' AND cr.case_event_sequence = st.sequence),
assets AS (SELECT id FROM axiom.assets WHERE scope_id IN (SELECT id FROM tree) AND created_at <= %(t)s),
retired AS (SELECT DISTINCT resource_id FROM axiom.audit_events WHERE action = 'asset.retired' AND occurred_at <= %(t)s),
occ AS (SELECT o.id FROM axiom.finding_occurrences o JOIN axiom.asset_versions av ON av.id = o.asset_version_id
         WHERE av.asset_id IN (SELECT id FROM assets) AND o.created_at <= %(t)s),
open_links AS (SELECT DISTINCT l.occurrence_id FROM axiom.case_occurrence_links l JOIN st ON st.id = l.case_id
                WHERE st.workflow <> 'closed' AND l.linked_at <= %(t)s AND (l.unlinked_at IS NULL OR l.unlinked_at > %(t)s)),
runs AS (SELECT r.* FROM axiom.ingestion_runs r WHERE r.scope_id IN (SELECT id FROM tree) AND r.finished_at <= %(t)s),
complete_obs AS (SELECT DISTINCT o.subject_asset_id AS asset_id, r.finished_at
                   FROM axiom.observations o JOIN runs r ON r.id = o.run_id
                  WHERE r.status = 'completed' AND r.coverage = 'complete' AND o.subject_asset_id IS NOT NULL),
owner_now AS (SELECT DISTINCT ON (o.case_id) o.case_id, o.basis FROM axiom.case_ownership o JOIN cases c ON c.id = o.case_id
               WHERE o.created_at <= %(t)s ORDER BY o.case_id, o.created_at DESC, o.id DESC),
timers AS (SELECT s.kind, CASE WHEN s.ended_at IS NOT NULL AND s.ended_at <= %(t)s THEN s.status
                               WHEN s.breached_at IS NOT NULL AND s.breached_at <= %(t)s THEN 'breached'
                               ELSE 'running' END AS status,
                  -- target is fixed per timer (due moves with pauses), so this is reproducible as of t
                  extract(epoch FROM (CASE WHEN s.ended_at IS NOT NULL AND s.ended_at <= %(t)s THEN s.ended_at
                                           ELSE %(t)s::timestamptz END) - s.started_at)
                    > extract(epoch FROM (s.due_at - s.started_at)) - s.paused_seconds AS over_target_gross
             FROM axiom.sla_timers s JOIN cases c ON c.id = s.case_id
            WHERE s.created_at <= %(t)s AND s.started_at <= %(t)s
              AND NOT (s.status = 'revised' AND s.ended_at <= %(t)s)),
tickets AS (SELECT r.id, (SELECT x.status_category FROM axiom.external_ticket_states x WHERE x.reference_id = r.id
                           AND x.observed_at <= %(t)s ORDER BY x.observed_at DESC, x.id DESC LIMIT 1) AS cat
              FROM axiom.external_references r JOIN cases c ON c.id = r.case_id WHERE r.created_at <= %(t)s)
SELECT jsonb_build_object(
  'denominators', jsonb_build_object(
     'cases', jsonb_build_object('total', (SELECT count(*) FROM st), 'open', (SELECT count(*) FROM st WHERE workflow <> 'closed'),
                                 'closed', (SELECT count(*) FROM st WHERE workflow = 'closed')),
     'occurrences', jsonb_build_object('total', (SELECT count(*) FROM occ),
                                       'linked_to_open_cases', (SELECT count(*) FROM open_links)),
     'assets', jsonb_build_object('total', (SELECT count(*) FROM assets),
                                  'retired', (SELECT count(*) FROM assets WHERE id::text IN (SELECT resource_id FROM retired)),
                                  'with_occurrences', (SELECT count(DISTINCT av.asset_id) FROM axiom.finding_occurrences o
                                     JOIN axiom.asset_versions av ON av.id = o.asset_version_id WHERE o.id IN (SELECT id FROM occ)))),
  'open_by_workflow', COALESCE((SELECT jsonb_object_agg(workflow, n) FROM (SELECT workflow, count(*) n FROM st
                                 WHERE workflow <> 'closed' GROUP BY workflow) x), '{}'),
  'open_by_priority', COALESCE((SELECT jsonb_object_agg(priority, n) FROM (SELECT priority, count(*) n FROM st
                                 WHERE workflow <> 'closed' GROUP BY priority) x), '{}'),
  'closed_by_reason', COALESCE((SELECT jsonb_object_agg(reason, n) FROM (SELECT reason, count(*) n FROM closures
                                 GROUP BY reason) x), '{}'),
  'unknowns', jsonb_build_object(
     'unprioritised_open_cases', (SELECT count(*) FROM st WHERE workflow <> 'closed' AND priority = 'pending'),
     'unassessed_open_cases', (SELECT count(*) FROM st WHERE workflow <> 'closed' AND assessment IS NULL),
     'inconclusive_assessments_open', (SELECT count(*) FROM st WHERE workflow <> 'closed' AND assessment = 'inconclusive'),
     'inconclusive_verifications_open', (SELECT count(*) FROM st WHERE workflow <> 'closed' AND verification = 'inconclusive'),
     'open_cases_without_resolved_owner', (SELECT count(*) FROM st LEFT JOIN owner_now o ON o.case_id = st.id
        WHERE st.workflow <> 'closed' AND (o.basis IS NULL OR o.basis = 'unresolved')),
     'assets_never_observed_complete', (SELECT count(*) FROM assets a WHERE NOT EXISTS
        (SELECT 1 FROM complete_obs co WHERE co.asset_id = a.id))),
  'accepted_exposure', jsonb_build_object(
     'active_acceptances', (SELECT count(*) FROM axiom.risk_acceptances ra JOIN cases c ON c.id = ra.case_id
        WHERE ra.starts_at <= %(t)s AND ra.expires_at > %(t)s AND (ra.ended_at IS NULL OR ra.ended_at > %(t)s)),
     'expiring_within_14_days', (SELECT count(*) FROM axiom.risk_acceptances ra JOIN cases c ON c.id = ra.case_id
        WHERE ra.starts_at <= %(t)s AND ra.expires_at > %(t)s AND (ra.ended_at IS NULL OR ra.ended_at > %(t)s)
          AND ra.expires_at <= %(t)s::timestamptz + interval '14 days')),
  'sla', jsonb_build_object(
     'triage', COALESCE((SELECT jsonb_object_agg(status, n) FROM (SELECT status, count(*) n FROM timers
                          WHERE kind = 'triage' GROUP BY status) x), '{}'),
     'remediation', COALESCE((SELECT jsonb_object_agg(status, n) FROM (SELECT status, count(*) n FROM timers
                               WHERE kind = 'remediation' GROUP BY status) x), '{}'),
     'remediation_over_target_on_gross_time', (SELECT count(*) FROM timers WHERE kind = 'remediation'
                                                 AND over_target_gross)),
  'external_tickets', COALESCE((SELECT jsonb_object_agg(COALESCE(cat, 'not_synchronised'), n)
                                  FROM (SELECT cat, count(*) n FROM tickets GROUP BY cat) x), '{}')
) AS content,
(SELECT COALESCE(jsonb_agg(src ORDER BY src->>'source'), '[]'::jsonb) FROM (
   SELECT jsonb_build_object(
     'source', r.source_kind || ':' || r.adapter || COALESCE(':' || r.connection_id::text, ''),
     'source_kind', r.source_kind, 'adapter', r.adapter, 'connection_id', r.connection_id,
     'declared_scope', (SELECT CASE WHEN x.source_kind = 'api_sync' THEN x.declared_scope
                                    ELSE COALESCE(x.declared_subject, '{"subject": "from file"}'::jsonb) END
                          FROM runs x WHERE x.source_kind = r.source_kind AND x.adapter = r.adapter
                           AND x.connection_id IS NOT DISTINCT FROM r.connection_id ORDER BY x.finished_at DESC LIMIT 1),
     'runs', count(*),
     'last_run_at', max(r.finished_at),
     'last_run_status', (array_agg(r.status ORDER BY r.finished_at DESC))[1],
     'last_successful_run_at', max(r.finished_at) FILTER (WHERE r.status = 'completed'),
     'last_successful_run_coverage', (array_agg(r.coverage ORDER BY r.finished_at DESC) FILTER (WHERE r.status = 'completed'))[1],
     'last_complete_coverage_at', max(r.finished_at) FILTER (WHERE r.status = 'completed' AND r.coverage = 'complete')) AS src
   FROM runs r GROUP BY r.source_kind, r.adapter, r.connection_id) s) AS sources
"""


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


def digest(doc) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def _freshness_policy(conn, as_of) -> tuple[dict, str | None]:
    from ..policies.service import DEFAULTS
    row = conn.execute(
        """SELECT * FROM axiom.policy_versions WHERE kind = 'freshness' AND published_at <= %s
            ORDER BY published_at DESC LIMIT 1""", (as_of,)).fetchone()
    return (row["definition"], str(row["id"])) if row else (DEFAULTS["freshness"], None)


class ReportService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer, store=None):
        self.conn, self.ctx, self.authz, self.store = conn, ctx, authz, store

    # ------------------------------------------------------------------ snapshots
    def compute(self, scope_id: UUID, as_of: datetime) -> dict:
        # timestamps inside the content must not depend on the session's time zone (reproducibility)
        self.conn.execute("SET LOCAL TimeZone = 'UTC'")
        row = self.conn.execute(_SQL, {"scope": scope_id, "t": as_of}).fetchone()
        content, sources = row["content"], row["sources"]
        policy, policy_id = _freshness_policy(self.conn, as_of)
        ages = policy["max_age_hours"]
        stale_or_never = 0
        for src in sources:
            max_age = ages.get(src["adapter"], ages["default"])
            last_ok = src["last_successful_run_at"]
            if last_ok is None:
                src["freshness"] = "never_succeeded"
            else:
                age_h = (as_of - datetime.fromisoformat(last_ok)).total_seconds() / 3600
                src["age_hours"] = round(age_h, 3)
                src["freshness"] = "fresh" if age_h <= max_age else "stale"
            src["max_age_hours"] = max_age
            src["completeness"] = src["last_successful_run_coverage"] or "unknown"
            if src["freshness"] != "fresh" or src["completeness"] != "complete":
                stale_or_never += 1
        content["coverage_by_source"] = sources
        content["unknowns"]["sources_not_fresh_or_not_complete"] = stale_or_never
        content["freshness_policy"] = {"policy_version_id": policy_id, "provisional": policy_id is None,
                                       "max_age_hours": ages}
        content["statements"] = STATEMENTS
        content["query_version"] = QUERY_VERSION
        content["as_of"] = as_of.isoformat()
        return content

    def generate(self, *, kind: str, scope_id: UUID, as_of: datetime | None = None) -> dict:
        if kind != "exposure_summary":
            raise ValidationFailed("unknown report kind")
        authority = self.authz.require("report.generate", scope_id)
        self.authz.require("report.read", scope_id)
        now = self.authz.now()
        as_of = as_of or now
        if as_of.tzinfo is None or as_of > now:
            raise ValidationFailed("as_of must be a timezone-aware time that is not in the future")
        content = self.compute(scope_id, as_of)
        row = self.conn.execute(
            """INSERT INTO axiom.report_snapshots(tenant_id, id, kind, scope_id, parameters, content, content_digest,
                   generated_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), kind, scope_id,
             Jsonb({"scope_id": str(scope_id), "as_of": as_of.isoformat(), "query_version": QUERY_VERSION}),
             Jsonb(content), digest(content), self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="report.generated", resource_type="report_snapshot",
                     resource_id=row["id"], detail={"kind": kind, "digest": row["content_digest"],
                                                    "as_of": as_of.isoformat(), "authority": authority.as_json()})
        return row

    def get(self, snapshot_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.report_snapshots WHERE id = %s", (snapshot_id,)).fetchone()
        if row is None or not self.authz.has("report.read", row["scope_id"]):
            raise NotFound("report not found", code="report_not_found")
        if digest(row["content"]) != row["content_digest"]:
            raise Conflict("report snapshot content does not match its digest", code="report_integrity")
        return row

    def export(self, snapshot_id: UUID, fmt: str) -> dict:
        snap = self.get(snapshot_id)
        authority = self.authz.require("report.export", snap["scope_id"])
        if fmt not in ("json", "csv"):
            raise ValidationFailed("format must be json or csv")
        return self._store_export(snap["id"], fmt, render(snap, fmt), authority)

    def _store_export(self, snapshot_id, fmt, body: bytes, authority) -> dict:
        export_id = uuid.uuid4()
        key = f"tenants/{self.ctx.tenant_id}/reports/{snapshot_id}/{export_id}.{fmt}"
        stored = TenantObjectStore(self.store, self.ctx.tenant_id).put(key, iter([body]), max_bytes=MAX_EXPORT_BYTES)
        row = self.conn.execute(
            """INSERT INTO axiom.report_exports(tenant_id, id, snapshot_id, format, object_key, sha256, size_bytes,
                   created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, export_id, snapshot_id, fmt, key, stored.sha256, stored.size,
             self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="report.exported", resource_type="report_export", resource_id=export_id,
                     detail={"snapshot_id": str(snapshot_id), "format": fmt, "sha256": stored.sha256,
                             "authority": authority.as_json()})
        return row

    def read_export(self, export_id: UUID) -> tuple[dict, bytes]:
        row = self.conn.execute("SELECT * FROM axiom.report_exports WHERE id = %s", (export_id,)).fetchone()
        if row is None:
            raise NotFound("export not found", code="export_not_found")
        snap = self.get(row["snapshot_id"])
        authority = self.authz.require("report.export", snap["scope_id"])
        if snap["kind"] == "evidence_package":
            self._case_scope_check(UUID(snap["parameters"]["case_id"]))
        data = b"".join(TenantObjectStore(self.store, self.ctx.tenant_id).get(row["object_key"]))
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise Conflict("stored export does not match its recorded digest", code="export_integrity")
        audit.record(self.conn, self.ctx, action="report.export_read", resource_type="report_export",
                     resource_id=export_id, detail={"authority": authority.as_json()})
        return row, data

    # ------------------------------------------------------------- evidence packages
    def _case_scope_check(self, case_id: UUID) -> dict:
        case = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
        if case is None or not self.authz.has("case.read", case["scope_id"]):
            raise NotFound("case not found", code="case_not_found")
        return case

    def evidence_package(self, case_id: UUID) -> dict:
        """Build, store and export (JSON) an auditor package for one case. Needs audit.read at the tenant root,
        case.read and report.export at the case scope; evidence content only where the classification is readable."""
        case = self._case_scope_check(case_id)
        root = self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]
        self.authz.require("audit.read", root)
        authority = self.authz.require("report.export", case["scope_id"])
        q = self.conn.execute
        decisions = list(q("""SELECT d.id, d.kind, d.outcome, d.rationale, d.limitations, d.actor_principal_id,
                                     d.authority, d.policy_version_id, d.supersedes_decision_id, d.recorded_at
                                FROM axiom.decisions d WHERE d.case_id = %s ORDER BY d.recorded_at, d.id""", (case_id,)))
        policy_ids = sorted({str(d["policy_version_id"]) for d in decisions if d["policy_version_id"]})
        policies = list(q("""SELECT id, kind, version, status, definition, definition_digest, provisional, drafted_by,
                                    published_by, published_at FROM axiom.policy_versions WHERE id::text = ANY(%s)
                              ORDER BY kind, version""", (policy_ids,)))
        events = list(q("""SELECT sequence, event_type, from_workflow, to_workflow, actor_principal_id, decision_id,
                                  audit_event_id, created_at, payload FROM axiom.case_events WHERE case_id = %s
                            ORDER BY sequence""", (case_id,)))
        ev_rows = list(q("""SELECT DISTINCT eo.id, eo.classification, eo.status, eo.observed_digest, eo.observed_size,
                                   eo.media_type, eo.object_key, eo.original_filename, de.relation, de.decision_id
                              FROM axiom.decision_evidence de JOIN axiom.evidence_objects eo ON eo.id = de.evidence_object_id
                              JOIN axiom.decisions d ON d.id = de.decision_id WHERE d.case_id = %s
                             ORDER BY eo.id""", (case_id,)))
        evidence = []
        for e in ev_rows:
            # Content needs evidence.read:<classification>. Metadata (digest, size, media type, filename) needs
            # evidence.read:<classification> or the explicit evidence.metadata:<classification>; without either,
            # only the reference and its classification are disclosed.
            item = {"evidence_id": str(e["id"]), "decision_id": str(e["decision_id"]), "relation": e["relation"],
                    "classification": e["classification"], "status": e["status"]}
            perm = READ_PERMISSION.get(e["classification"])
            meta_perm = META_PERMISSION.get(e["classification"])
            readable = perm is None or self.authz.has(perm, case["scope_id"])
            meta_ok = readable or self.authz.has(meta_perm, case["scope_id"])
            if meta_ok:
                item.update(sha256=e["observed_digest"], size=e["observed_size"], media_type=e["media_type"],
                            filename=e["original_filename"])
            else:
                item["metadata_withheld"] = f"requester lacks {perm} and {meta_perm}"
            if not readable:
                item["content"] = None
                item["withheld"] = f"requester lacks {perm}"
            elif e["status"] != "verified" or (e["observed_size"] or 0) > MAX_INLINE_EVIDENCE:
                item["content"] = None
                item["withheld"] = "not verified" if e["status"] != "verified" else "larger than inline limit"
            else:
                data = b"".join(TenantObjectStore(self.store, self.ctx.tenant_id).get(e["object_key"]))
                if hashlib.sha256(data).hexdigest() != e["observed_digest"]:
                    raise Conflict("evidence content does not match its verified digest", code="evidence_integrity")
                item["content_base64"] = base64.b64encode(data).decode()
                audit.record(self.conn, self.ctx, action="evidence.read", resource_type="evidence", resource_id=e["id"],
                             detail={"purpose": "evidence_package", "case_id": str(case_id)})
            evidence.append(item)
        package = {
            "case": {k: case[k] for k in ("id", "scope_id", "title", "workflow", "assessment", "priority",
                                          "disposition", "record_version", "created_at")},
            "events": events, "decisions": decisions, "policy_versions": policies, "evidence": evidence,
            "verification_runs": list(q("SELECT * FROM axiom.verification_runs WHERE case_id = %s ORDER BY recorded_at",
                                        (case_id,))),
            "remediation_reports": list(q("SELECT * FROM axiom.remediation_reports WHERE case_id = %s ORDER BY created_at",
                                          (case_id,))),
            "closure_records": list(q("SELECT * FROM axiom.closure_records WHERE case_id = %s ORDER BY created_at",
                                      (case_id,))),
            "risk_acceptances": list(q("SELECT * FROM axiom.risk_acceptances WHERE case_id = %s ORDER BY created_at",
                                       (case_id,))),
            "risk_requests": list(q("SELECT * FROM axiom.risk_acceptance_requests WHERE case_id = %s ORDER BY created_at",
                                    (case_id,))),
            "proposals": list(q("""SELECT v.* FROM axiom.action_proposal_versions v WHERE v.case_id = %s
                                   ORDER BY v.created_at""", (case_id,))),
            "approvals": list(q("""SELECT a.id, a.proposal_version_id, a.payload_digest, a.decision, a.approver_principal_id,
                                          a.authority_snapshot, a.rationale, a.valid_until, a.max_uses, a.uses_reserved,
                                          a.uses_released, a.status, a.revoked_at, a.revocation_reason, a.created_at
                                     FROM axiom.approvals a JOIN axiom.action_proposals p ON p.id = a.proposal_id
                                    WHERE p.case_id = %s ORDER BY a.created_at""", (case_id,))),
            "executions": list(q("""SELECT e.id, e.proposal_version_id, e.approval_id, e.state, e.external_ref,
                                           e.external_operation_id, e.created_at, e.updated_at
                                      FROM axiom.action_executions e JOIN axiom.action_proposals p ON p.id = e.proposal_id
                                     WHERE p.case_id = %s ORDER BY e.created_at""", (case_id,))),
            "external_references": list(q("SELECT * FROM axiom.external_references WHERE case_id = %s", (case_id,))),
            "ticket_states": list(q("""SELECT s.* FROM axiom.external_ticket_states s JOIN axiom.external_references r
                                         ON r.id = s.reference_id WHERE r.case_id = %s ORDER BY s.observed_at""",
                                    (case_id,))),
            "ownership": list(q("SELECT * FROM axiom.case_ownership WHERE case_id = %s ORDER BY created_at", (case_id,))),
            "sla_timers": list(q("SELECT * FROM axiom.sla_timers WHERE case_id = %s ORDER BY created_at", (case_id,))),
            "generated_for": str(self.ctx.principal_id),
            "withheld_evidence": sum(1 for e in evidence if e.get("content") is None and "withheld" in e),
            "withheld_metadata": sum(1 for e in evidence if "metadata_withheld" in e),
        }
        package = json.loads(canonical(package))
        row = self.conn.execute(
            """INSERT INTO axiom.report_snapshots(tenant_id, id, kind, scope_id, parameters, content, content_digest,
                   generated_by) VALUES (%s, %s, 'evidence_package', %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), case["scope_id"], Jsonb({"case_id": str(case_id)}), Jsonb(package),
             digest(package), self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="report.evidence_package", resource_type="finding_case",
                     resource_id=case_id, detail={"snapshot_id": str(row["id"]), "digest": row["content_digest"],
                                                  "withheld_evidence": package["withheld_evidence"],
                                                  "authority": authority.as_json()})
        export = self._store_export(row["id"], "json", canonical({"package": package,
                                                                 "content_digest": row["content_digest"]}), authority)
        return {"snapshot": row, "export": export}


def render(snap: dict, fmt: str) -> bytes:
    meta = {"snapshot_id": str(snap["id"]), "kind": snap["kind"], "scope_id": str(snap["scope_id"]),
            "generated_at": snap["generated_at"].isoformat(), "content_digest": snap["content_digest"],
            "parameters": snap["parameters"]}
    if fmt == "json":
        return canonical({"snapshot": meta, "content": snap["content"]})
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["section", "key", "value"])
    for k, v in sorted(meta.items()):
        w.writerow(["snapshot", k, json.dumps(v, sort_keys=True, default=str) if isinstance(v, dict) else v])

    def walk(prefix, value):
        if isinstance(value, dict):
            for k, v in sorted(value.items()):
                walk(f"{prefix}.{k}" if prefix else k, v)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(f"{prefix}[{i}]", v)
        else:
            section, _, key = prefix.partition(".")
            w.writerow([section, key, value])
    walk("", snap["content"])
    return buf.getvalue().encode()
