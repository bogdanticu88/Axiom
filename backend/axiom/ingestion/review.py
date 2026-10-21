"""Review of asset identity candidates and asset inspection.

Resolving a candidate records a human decision ('confirmed_same', 'confirmed_distinct', 'dismissed') with
rationale. It does NOT merge assets yet: reversible merge/split execution (AST-03) is planned. A
'confirmed_same' decision is therefore an auditable assertion that a later merge command will act on.
"""
from __future__ import annotations

from uuid import UUID

import psycopg

from .. import audit
from ..access import Authorizer
from ..db import TenantContext
from ..errors import Conflict, NotFound, ValidationFailed


class IdentityReview:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    def _root(self) -> UUID:
        return self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]

    def list_open(self, limit: int = 100) -> list[dict]:
        """Open candidates whose assets are ALL within scopes the caller may read."""
        scopes = self.authz.readable_scopes("asset.read")
        if not scopes:
            return []
        return list(self.conn.execute(
            """WITH RECURSIVE covered(id) AS (SELECT id FROM axiom.scopes WHERE id = ANY(%s)
                   UNION SELECT s.id FROM axiom.scopes s JOIN covered ON s.parent_id = covered.id)
               SELECT c.*, (SELECT jsonb_agg(jsonb_build_object('id', a.id, 'display_name', a.display_name,
                       'kind', a.asset_kind, 'identity_status', a.identity_status))
                       FROM axiom.assets a WHERE a.id = ANY(c.asset_ids)) AS assets
                 FROM axiom.identity_candidates c
                WHERE c.status = 'open'
                  AND NOT EXISTS (SELECT 1 FROM axiom.assets a WHERE a.id = ANY(c.asset_ids)
                                   AND a.scope_id NOT IN (SELECT id FROM covered))
                ORDER BY c.created_at LIMIT %s""", (scopes, limit)))

    def resolve(self, candidate_id: UUID, *, expected_version: int, outcome: str, rationale: str) -> dict:
        if outcome not in ("confirmed_same", "confirmed_distinct", "dismissed"):
            raise ValidationFailed("outcome must be confirmed_same, confirmed_distinct or dismissed")
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        cand = self.conn.execute("SELECT * FROM axiom.identity_candidates WHERE id = %s", (candidate_id,)).fetchone()
        if cand is None:
            raise NotFound("identity candidate not found")
        scopes = {r["scope_id"] for r in self.conn.execute(
            "SELECT scope_id FROM axiom.assets WHERE id = ANY(%s)", (cand["asset_ids"],))}
        authority = None
        for scope in scopes:   # the reviewer needs authority over every asset involved
            authority = self.authz.require("identity.review", scope)
        row = self.conn.execute(
            """UPDATE axiom.identity_candidates SET status = %s, resolved_by = %s, resolved_at = clock_timestamp(),
                      resolution_rationale = %s, record_version = record_version + 1
                WHERE id = %s AND record_version = %s AND status = 'open' RETURNING *""",
            (outcome, self.ctx.principal_id, rationale, candidate_id, expected_version)).fetchone()
        if row is None:
            raise Conflict("candidate changed or already resolved", code="stale_version")
        audit.record(self.conn, self.ctx, action="identity.candidate_resolved", resource_type="identity_candidate",
                     resource_id=candidate_id, detail={"outcome": outcome, "rationale": rationale,
                                                       "asset_ids": [str(a) for a in cand["asset_ids"]],
                                                       "authority": authority.as_json() if authority else None})
        return row

    def asset(self, asset_id: UUID) -> dict:
        asset = self.conn.execute("SELECT * FROM axiom.assets WHERE id = %s", (asset_id,)).fetchone()
        if asset is None:
            raise NotFound("asset not found", code="asset_not_found")
        self.authz.require("asset.read", asset["scope_id"])
        return {
            "asset": asset,
            "identifiers": list(self.conn.execute(
                "SELECT namespace, value, strength, origin, valid_from, valid_until FROM axiom.asset_identifiers "
                "WHERE asset_id = %s ORDER BY strength, namespace", (asset_id,))),
            "versions": list(self.conn.execute(
                "SELECT * FROM axiom.asset_versions WHERE asset_id = %s ORDER BY observed_at DESC LIMIT 100", (asset_id,))),
            "business_context": list(self.conn.execute(
                "SELECT * FROM axiom.business_context_versions WHERE asset_id = %s ORDER BY effective_from DESC LIMIT 20",
                (asset_id,))),
            "open_candidates": list(self.conn.execute(
                "SELECT id, method, asset_ids FROM axiom.identity_candidates WHERE status = 'open' AND %s = ANY(asset_ids)",
                (asset_id,))),
        }
