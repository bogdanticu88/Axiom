"""Versioned policies (priority, ownership, SLA, freshness).

Each version is drafted with a rationale, validated, digested by the database, and published by a **different**
principal holding ``policy.publish`` (independent approval). Publishing supersedes the previous published version of
the same kind; definitions never change. Decisions record the policy version they used (``decisions.policy_version_id``)
so a later policy change never rewrites earlier decisions (A14).

When no version of a kind has been published, a **built-in provisional default** applies and is labelled as such in
every decision or timer that uses it. Thresholds are provisional until the business confirms them (Specification S 17).
"""
from __future__ import annotations

import uuid
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, Forbidden, NotFound, ValidationFailed

SEVERITIES = ("critical", "high", "medium", "low", "info")
CRITICALITIES = ("critical", "high", "medium", "low")
PRIORITIES = ("urgent", "high", "medium", "low")

DEFAULTS = {
    # Built-in provisional defaults (labelled provisional wherever used).
    "priority": {
        "matrix": {
            "critical": {"critical": "urgent", "high": "urgent", "medium": "high", "low": "high"},
            "high": {"critical": "urgent", "high": "high", "medium": "high", "low": "medium"},
            "medium": {"critical": "high", "high": "medium", "medium": "medium", "low": "low"},
            "low": {"critical": "medium", "high": "low", "medium": "low", "low": "low"},
            "info": {"critical": "low", "high": "low", "medium": "low", "low": "low"},
        },
        # Missing inputs are substituted conservatively and recorded as limitations, never silently dropped.
        "unknown_severity": "high",
        "unknown_criticality": "high",
    },
    "ownership": {"rules": []},
    "sla": {"triage_days": 7, "remediation_days": {"urgent": 7, "high": 30, "medium": 90, "low": 180},
            "pause_on_deferral": True},
    "freshness": {"max_age_hours": {"default": 168, "tenable_vm": 48, "azure_resource_graph": 48,
                                    "trivy_json": 336, "sarif_2_1_0": 336}},
}

_OWNERSHIP_KEYS = {"scope_id", "asset_kind", "owner_ref", "environment", "criticality"}


def validate(kind: str, d: dict) -> dict:
    if kind == "priority":
        m = d.get("matrix")
        if not isinstance(m, dict) or set(m) != set(SEVERITIES):
            raise ValidationFailed(f"priority matrix needs exactly these severities: {SEVERITIES}")
        for sev, row in m.items():
            if not isinstance(row, dict) or set(row) != set(CRITICALITIES) or not set(row.values()) <= set(PRIORITIES):
                raise ValidationFailed(f"matrix row {sev} needs {CRITICALITIES} mapped to {PRIORITIES}")
        if d.get("unknown_severity") not in SEVERITIES or d.get("unknown_criticality") not in CRITICALITIES:
            raise ValidationFailed("unknown_severity and unknown_criticality must name a bucket")
        extra = set(d) - {"matrix", "unknown_severity", "unknown_criticality"}
    elif kind == "ownership":
        rules = d.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ValidationFailed("ownership policy needs at least one rule")
        ids = set()
        for r in rules:
            if not isinstance(r, dict) or not r.get("id") or r["id"] in ids:
                raise ValidationFailed("each rule needs a unique id")
            ids.add(r["id"])
            match = r.get("match")
            if not isinstance(match, dict) or not match or not set(match) <= _OWNERSHIP_KEYS:
                raise ValidationFailed(f"rule {r['id']}: match on explicit context keys only {sorted(_OWNERSHIP_KEYS)}")
            try:
                UUID(str(r.get("owner_principal_id")))
            except ValueError as exc:
                raise ValidationFailed(f"rule {r['id']}: owner_principal_id must be a principal id") from exc
        extra = set(d) - {"rules"}
    elif kind == "sla":
        rd = d.get("remediation_days")
        if not isinstance(d.get("triage_days"), int) or d["triage_days"] < 1 or not isinstance(rd, dict) \
                or set(rd) != set(PRIORITIES) or not all(isinstance(v, int) and v >= 1 for v in rd.values()):
            raise ValidationFailed("sla needs triage_days and remediation_days for every priority (positive days)")
        extra = set(d) - {"triage_days", "remediation_days", "pause_on_deferral"}
    elif kind == "freshness":
        ages = d.get("max_age_hours")
        if not isinstance(ages, dict) or "default" not in ages or not all(isinstance(v, int) and v >= 1
                                                                          for v in ages.values()):
            raise ValidationFailed("freshness needs max_age_hours with a default (positive hours)")
        extra = set(d) - {"max_age_hours"}
    else:
        raise ValidationFailed("unknown policy kind")
    if extra:
        raise ValidationFailed(f"unknown policy fields: {sorted(extra)}")
    return d


def current(conn: psycopg.Connection, kind: str) -> tuple[dict, UUID | None, bool]:
    """(definition, policy_version_id or None for the built-in default, provisional)."""
    row = conn.execute("SELECT * FROM axiom.policy_versions WHERE kind = %s AND status = 'published'", (kind,)).fetchone()
    if row is None:
        return DEFAULTS[kind], None, True
    return row["definition"], row["id"], row["provisional"]


class PolicyService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    def _root(self) -> UUID:
        return self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]

    def draft(self, *, kind: str, definition: dict, rationale: str, provisional: bool = True) -> dict:
        authority = self.authz.require("policy.draft", self._root())
        validate(kind, definition)
        version = self.conn.execute("SELECT COALESCE(max(version), 0) + 1 AS v FROM axiom.policy_versions WHERE kind = %s",
                                    (kind,)).fetchone()["v"]
        row = self.conn.execute(
            """INSERT INTO axiom.policy_versions(tenant_id, id, kind, version, status, definition, definition_digest,
                   provisional, rationale, drafted_by) VALUES (%s, %s, %s, %s, 'draft', %s, '', %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), kind, version, Jsonb(definition), provisional, rationale,
             self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="policy.drafted", resource_type="policy_version", resource_id=row["id"],
                     detail={"kind": kind, "version": version, "digest": row["definition_digest"],
                             "authority": authority.as_json()})
        return row

    def publish(self, policy_id: UUID, *, rationale: str) -> dict:
        authority = self.authz.require("policy.publish", self._root())
        row = self.conn.execute("SELECT * FROM axiom.policy_versions WHERE id = %s FOR UPDATE", (policy_id,)).fetchone()
        if row is None:
            raise NotFound("policy not found", code="policy_not_found")
        if row["status"] != "draft":
            raise Conflict(f"policy is {row['status']}", code="policy_not_draft")
        if row["drafted_by"] == self.ctx.principal_id:
            raise Forbidden("a policy must be published by someone other than its author",
                            code="separation_of_duties")
        self.conn.execute("""UPDATE axiom.policy_versions SET status = 'superseded', record_version = record_version + 1
                              WHERE kind = %s AND status = 'published'""", (row["kind"],))
        out = self.conn.execute(
            """UPDATE axiom.policy_versions SET status = 'published', published_by = %s, published_at = clock_timestamp(),
                      record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (self.ctx.principal_id, policy_id)).fetchone()
        audit.record(self.conn, self.ctx, action="policy.published", resource_type="policy_version",
                     resource_id=policy_id, detail={"kind": row["kind"], "version": row["version"],
                                                    "rationale": rationale, "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="policy.published", aggregate_type="policy_version",
                       aggregate_id=policy_id, payload={"kind": row["kind"], "version": row["version"]})
        return out

    def list(self, kind: str | None = None) -> list[dict]:
        self.authz.require("policy.draft", self._root())
        return list(self.conn.execute(
            "SELECT * FROM axiom.policy_versions WHERE (%(k)s::text IS NULL OR kind = %(k)s) ORDER BY kind, version",
            {"k": kind}))
