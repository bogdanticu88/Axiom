"""Minimal asset records needed for deployment-bound verification (Phase A).

Phase B replaces direct occurrence recording with the ingestion pipeline and
adds identity candidates, merges and splits. Nothing here merges assets or
treats a CVE, IP, name or tag as identity.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

import psycopg

from ... import audit
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, NotFound

ASSET_KINDS = {"host", "container_image", "workload", "cloud_resource", "repository", "application", "unknown"}


class AssetService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    def create_asset(self, *, scope_id: UUID, kind: str, display_name: str) -> dict:
        self.authz.require("asset.manage", scope_id)
        asset_id = uuid.uuid4()
        row = self.conn.execute(
            """INSERT INTO axiom.assets(tenant_id, id, scope_id, asset_kind, display_name)
               VALUES (%s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, asset_id, scope_id, kind, display_name)).fetchone()
        audit.record(self.conn, self.ctx, action="asset.create", resource_type="asset", resource_id=asset_id)
        return row

    def _asset(self, asset_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.assets WHERE id = %s", (asset_id,)).fetchone()
        if row is None:
            raise NotFound("asset not found", code="asset_not_found")
        return row

    def record_version(self, *, asset_id: UUID, observed_at: datetime, deployment_digest: str | None = None,
                       version_label: str | None = None, source_evidence_id: UUID | None = None) -> dict:
        asset = self._asset(asset_id)
        self.authz.require("asset.manage", asset["scope_id"])
        version_id = uuid.uuid4()
        row = self.conn.execute(
            """INSERT INTO axiom.asset_versions(tenant_id, id, asset_id, deployment_digest, version_label,
                   observed_at, source_evidence_id) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, version_id, asset_id, deployment_digest, version_label, observed_at,
             source_evidence_id)).fetchone()
        audit.record(self.conn, self.ctx, action="asset.version_recorded", resource_type="asset_version",
                     resource_id=version_id, detail={"asset_id": str(asset_id), "digest": deployment_digest})
        return row

    def record_occurrence(self, *, source_system: str, source_finding_id: str, asset_version_id: UUID,
                          component_locator: str = "", vulnerability_ref: str | None = None) -> dict:
        version = self.conn.execute(
            """SELECT v.*, a.scope_id FROM axiom.asset_versions v JOIN axiom.assets a ON a.id = v.asset_id
                WHERE v.id = %s""", (asset_version_id,)).fetchone()
        if version is None:
            raise NotFound("asset version not found", code="asset_version_not_found")
        self.authz.require("asset.manage", version["scope_id"])
        row = self.conn.execute(
            """INSERT INTO axiom.finding_occurrences(tenant_id, id, source_system, source_finding_id,
                   asset_version_id, component_locator, vulnerability_ref)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id, source_system, source_finding_id, asset_version_id, component_locator)
               DO NOTHING RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), source_system, source_finding_id, asset_version_id,
             component_locator, vulnerability_ref)).fetchone()
        if row is None:  # replay: return the existing occurrence instead of duplicating it
            row = self.conn.execute(
                """SELECT * FROM axiom.finding_occurrences WHERE source_system = %s AND source_finding_id = %s
                     AND asset_version_id = %s AND component_locator = %s""",
                (source_system, source_finding_id, asset_version_id, component_locator)).fetchone()
        return row

    def retire(self, *, asset_id: UUID, expected_version: int, evidence_id: UUID, rationale: str) -> dict:
        asset = self._asset(asset_id)
        authority = self.authz.require("asset.manage", asset["scope_id"])
        if asset["record_version"] != expected_version:
            raise Conflict("asset was changed by another request", code="stale_version")
        evidence = self.conn.execute("SELECT status FROM axiom.evidence_objects WHERE id = %s",
                                     (evidence_id,)).fetchone()
        if evidence is None:
            raise NotFound("evidence not found", code="evidence_not_found")
        if evidence["status"] != "verified":
            raise Conflict("retirement requires verified lifecycle evidence", code="evidence_not_verified")
        row = self.conn.execute(
            """UPDATE axiom.assets SET lifecycle_status = 'retired', retirement_evidence_id = %s,
                      record_version = record_version + 1 WHERE id = %s AND record_version = %s RETURNING *""",
            (evidence_id, asset_id, expected_version)).fetchone()
        if row is None:
            raise Conflict("asset was changed by another request", code="stale_version")
        audit.record(self.conn, self.ctx, action="asset.retired", resource_type="asset", resource_id=asset_id,
                     detail={"evidence_id": str(evidence_id), "rationale": rationale,
                             "authority": authority.as_json()})
        return row
