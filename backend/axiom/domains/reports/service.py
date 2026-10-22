"""Immutable report snapshots and file exports (Implementation Plan Phase D, RISK-04, VER-05).

A snapshot is computed by **one SQL statement** (one consistent read) over the requested scope and its descendants,
stored with a SHA-256 digest of its canonical JSON, and never changed. Accepted risk, dismissals, duplicates and
retired assets are reported separately from verified remediation, and accepted exposure stays visible (RISK-04).
Exports render a snapshot to JSON or CSV in tenant object storage; their digest is checked on every read.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, NotFound, ValidationFailed
from ..evidence.objectstore import TenantObjectStore

MAX_EXPORT_BYTES = 50 * 1024 * 1024

_EXPOSURE_SQL = """
WITH RECURSIVE tree(id) AS (SELECT %(scope)s::uuid UNION ALL SELECT s.id FROM axiom.scopes s JOIN tree ON s.parent_id = tree.id),
cases AS (SELECT * FROM axiom.finding_cases WHERE scope_id IN (SELECT id FROM tree)),
closures AS (SELECT cr.reason FROM axiom.closure_records cr JOIN cases c ON c.id = cr.case_id
              WHERE cr.case_event_sequence = c.record_version AND c.workflow = 'closed')
SELECT jsonb_build_object(
  'as_of', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'cases_total', (SELECT count(*) FROM cases),
  'open_by_workflow', COALESCE((SELECT jsonb_object_agg(workflow, n) FROM (SELECT workflow, count(*) n FROM cases
                                 WHERE workflow <> 'closed' GROUP BY workflow) x), '{}'),
  'open_by_priority', COALESCE((SELECT jsonb_object_agg(priority, n) FROM (SELECT priority, count(*) n FROM cases
                                 WHERE workflow <> 'closed' GROUP BY priority) x), '{}'),
  'closed_by_reason', COALESCE((SELECT jsonb_object_agg(reason, n) FROM (SELECT reason, count(*) n FROM closures
                                 GROUP BY reason) x), '{}'),
  'accepted_exposure', jsonb_build_object(
      'active_acceptances', (SELECT count(*) FROM axiom.risk_acceptances a JOIN cases c ON c.id = a.case_id
                              WHERE a.status = 'active'),
      'expiring_within_14_days', (SELECT count(*) FROM axiom.risk_acceptances a JOIN cases c ON c.id = a.case_id
                              WHERE a.status = 'active' AND a.expires_at <= clock_timestamp() + interval '14 days')),
  'sla', COALESCE((SELECT jsonb_object_agg(status, n) FROM (SELECT s.status, count(*) n FROM axiom.case_slas s
                    JOIN cases c ON c.id = s.case_id WHERE s.status <> 'superseded' GROUP BY s.status) x), '{}'),
  'external_tickets', COALESCE((SELECT jsonb_object_agg(cat, n) FROM (
      SELECT COALESCE((SELECT st.status_category FROM axiom.external_ticket_states st WHERE st.reference_id = r.id
                        ORDER BY st.observed_at DESC, st.id DESC LIMIT 1), 'not_synchronised') AS cat, count(*) n
        FROM axiom.external_references r JOIN cases c ON c.id = r.case_id GROUP BY 1) x), '{}'),
  'action_executions', COALESCE((SELECT jsonb_object_agg(state, n) FROM (SELECT e.state, count(*) n
      FROM axiom.action_executions e JOIN axiom.action_proposals p ON p.id = e.proposal_id JOIN cases c ON c.id = p.case_id
      GROUP BY e.state) x), '{}')
) AS content
"""


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


def digest(doc) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


class ReportService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer, store=None):
        self.conn, self.ctx, self.authz, self.store = conn, ctx, authz, store

    def generate(self, *, kind: str, scope_id: UUID) -> dict:
        if kind != "exposure_summary":
            raise ValidationFailed("unknown report kind")
        authority = self.authz.require("report.generate", scope_id)
        self.authz.require("report.read", scope_id)
        content = self.conn.execute(_EXPOSURE_SQL, {"scope": scope_id}).fetchone()["content"]
        row = self.conn.execute(
            """INSERT INTO axiom.report_snapshots(tenant_id, id, kind, scope_id, parameters, content, content_digest,
                   generated_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), kind, scope_id, Jsonb({"scope_id": str(scope_id)}), Jsonb(content),
             digest(content), self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="report.generated", resource_type="report_snapshot",
                     resource_id=row["id"], detail={"kind": kind, "digest": row["content_digest"],
                                                    "authority": authority.as_json()})
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
        body = render(snap, fmt)
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
        data = b"".join(TenantObjectStore(self.store, self.ctx.tenant_id).get(row["object_key"]))
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise Conflict("stored export does not match its recorded digest", code="export_integrity")
        audit.record(self.conn, self.ctx, action="report.export_read", resource_type="report_export",
                     resource_id=export_id, detail={"authority": authority.as_json()})
        return row, data


def render(snap: dict, fmt: str) -> bytes:
    meta = {"snapshot_id": str(snap["id"]), "kind": snap["kind"], "scope_id": str(snap["scope_id"]),
            "generated_at": snap["generated_at"].isoformat(), "content_digest": snap["content_digest"]}
    if fmt == "json":
        return canonical({"snapshot": meta, "content": snap["content"]})
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["section", "key", "value"])
    for k, v in sorted(meta.items()):
        w.writerow(["snapshot", k, v])
    for section, value in sorted(snap["content"].items()):
        if isinstance(value, dict):
            for k, v in sorted(value.items()):
                w.writerow([section, k, v])
        else:
            w.writerow([section, "", value])
    return buf.getvalue().encode()
