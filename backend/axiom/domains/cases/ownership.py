"""Ownership routing (Design S 9: ownership does not automatically grant approval authority).

Routing evaluates the published ownership policy's rules **in order** against explicit context only: the case scope,
and for each affected asset its kind and latest asserted business context (owner reference, environment,
criticality). The first rule whose every key matches assigns its principal, provided that principal is an active
member; otherwise the case goes to the unresolved-owner queue with the reason. Manual overrides need
``ownership.override`` and a reason. Every routing and override is an append-only history row. Ownership never adds a
role binding or any permission: owners act only through the roles they already hold.
"""
from __future__ import annotations

import uuid
from uuid import UUID

from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...errors import NotFound, ValidationFailed
from ..policies.service import current
from .service import CaseService


def _context(svc: CaseService, case: dict) -> dict:
    assets = svc.conn.execute(
        """SELECT DISTINCT a.id, a.asset_kind FROM axiom.case_occurrence_links l
             JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
             JOIN axiom.asset_versions av ON av.id = o.asset_version_id JOIN axiom.assets a ON a.id = av.asset_id
            WHERE l.case_id = %s AND l.unlinked_at IS NULL ORDER BY a.id""", (case["id"],)).fetchall()
    out = []
    for a in assets:
        ctx = svc.conn.execute(
            """SELECT owner_ref, environment, criticality, basis FROM axiom.business_context_versions
                WHERE asset_id = %s AND effective_from <= clock_timestamp()
                ORDER BY effective_from DESC, recorded_at DESC LIMIT 1""", (a["id"],)).fetchone() or {}
        out.append({"asset_id": str(a["id"]), "asset_kind": a["asset_kind"], "owner_ref": ctx.get("owner_ref"),
                    "environment": ctx.get("environment"), "criticality": ctx.get("criticality"),
                    "basis": ctx.get("basis")})
    return {"scope_id": str(case["scope_id"]), "assets": out}


def _matches(rule: dict, context: dict) -> bool:
    m = rule["match"]
    if "scope_id" in m and m["scope_id"] != context["scope_id"]:
        return False
    asset_keys = set(m) - {"scope_id"}
    if not asset_keys:
        return True
    return any(all(a.get(k) is not None and str(a.get(k)) == str(m[k]) for k in asset_keys) for a in context["assets"])


def _record(svc, case, owner, basis, reason, context, policy_id=None, rule_id=None) -> dict:
    row = svc.conn.execute(
        """INSERT INTO axiom.case_ownership(tenant_id, id, case_id, owner_principal_id, basis, policy_version_id, rule_id,
               reason, context, assigned_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
        (svc.ctx.tenant_id, uuid.uuid4(), case["id"], owner, basis, policy_id, rule_id, reason, Jsonb(context),
         svc.ctx.principal_id)).fetchone()
    audit.record(svc.conn, svc.ctx, action=f"ownership.{basis}", resource_type="finding_case", resource_id=case["id"],
                 detail={"owner_principal_id": str(owner) if owner else None, "rule_id": rule_id, "reason": reason})
    outbox.enqueue(svc.conn, svc.ctx, topic=f"ownership.{basis}", aggregate_type="finding_case",
                   aggregate_id=case["id"], payload={"owner_principal_id": str(owner) if owner else None})
    return row


def route(svc: CaseService, case_id: UUID) -> dict:
    case = svc._load(case_id)
    svc.authz.require("ownership.route", case["scope_id"])
    definition, policy_id, _ = current(svc.conn, "ownership")
    context = _context(svc, case)
    for rule in definition.get("rules", []):
        if _matches(rule, context):
            owner = UUID(str(rule["owner_principal_id"]))
            member = svc.conn.execute("SELECT status FROM axiom.memberships WHERE principal_id = %s", (owner,)).fetchone()
            if member is None or member["status"] != "active":
                return _record(svc, case, None, "unresolved",
                               f"rule {rule['id']} names a principal without an active membership", context)
            if policy_id is None:   # built-in default has no rules; kept for completeness
                return _record(svc, case, None, "unresolved", "no published ownership policy", context)
            return _record(svc, case, owner, "rule", f"matched rule {rule['id']}", context, policy_id, rule["id"])
    reason = "no published ownership policy" if policy_id is None else "no rule matched the explicit context"
    if not context["assets"]:
        reason += "; the case has no linked asset"
    elif all(a["owner_ref"] is None and a["environment"] is None for a in context["assets"]):
        reason += "; no business context has been asserted for its assets"
    return _record(svc, case, None, "unresolved", reason, context, policy_id)


def override(svc: CaseService, case_id: UUID, *, owner_principal_id: UUID, reason: str) -> dict:
    if not reason.strip():
        raise ValidationFailed("a reason is required")
    case = svc._load(case_id)
    svc.authz.require("ownership.override", case["scope_id"])
    member = svc.conn.execute("SELECT status FROM axiom.memberships WHERE principal_id = %s",
                              (owner_principal_id,)).fetchone()
    if member is None or member["status"] != "active":
        raise ValidationFailed("the owner must be an active member of this tenant")
    return _record(svc, case, owner_principal_id, "manual_override", reason, _context(svc, case))


def current_owner(svc: CaseService, case_id: UUID) -> dict | None:
    return svc.conn.execute("SELECT * FROM axiom.case_ownership WHERE case_id = %s ORDER BY created_at DESC, id DESC "
                            "LIMIT 1", (case_id,)).fetchone()


def history(svc: CaseService, case_id: UUID) -> list[dict]:
    case = svc._load(case_id)
    svc.authz.require("case.read", case["scope_id"])
    return list(svc.conn.execute("SELECT * FROM axiom.case_ownership WHERE case_id = %s ORDER BY created_at, id",
                                 (case_id,)))


def unresolved_queue(svc: CaseService, limit: int = 200) -> list[dict]:
    """Open cases whose current ownership is unresolved or that were never routed, readable by the caller."""
    scopes = svc.authz.readable_scopes("case.read")
    if not scopes:
        return []
    return list(svc.conn.execute(
        """WITH RECURSIVE tree(id) AS (SELECT unnest(%(scopes)s::uuid[]) UNION
                                       SELECT s.id FROM axiom.scopes s JOIN tree ON s.parent_id = tree.id),
                latest AS (SELECT DISTINCT ON (case_id) * FROM axiom.case_ownership ORDER BY case_id, created_at DESC, id DESC)
           SELECT c.id, c.title, c.workflow, c.priority, c.scope_id, l.reason AS unresolved_reason, l.created_at AS since
             FROM axiom.finding_cases c LEFT JOIN latest l ON l.case_id = c.id
            WHERE c.workflow <> 'closed' AND c.scope_id IN (SELECT id FROM tree)
              AND (l.case_id IS NULL OR l.basis = 'unresolved')
            ORDER BY c.created_at LIMIT %(limit)s""", {"scopes": scopes, "limit": limit}))


def require_known(row):
    if row is None:
        raise NotFound("no ownership recorded", code="owner_not_found")
    return row


SWEEP_KIND = "cases.ownership_sweep"


class OwnershipSweepHandler:
    """Routes open cases that have never been routed, and re-routes unresolved ones once their inputs change (a newer
    published ownership policy or newer business context for a linked asset). Unchanged unresolved cases are not
    re-routed, so the history does not fill with identical rows. Runs as the system principal (ownership.route)."""
    kind = SWEEP_KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc):
        from ...access import Authorizer
        from ...jobs import Done
        routed = []
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            svc = CaseService(conn, jc.ctx, Authorizer(conn, jc.ctx))
            for c in conn.execute("""
                    SELECT c.id FROM axiom.finding_cases c
                      LEFT JOIN LATERAL (SELECT o.basis, o.created_at FROM axiom.case_ownership o WHERE o.case_id = c.id
                                          ORDER BY o.created_at DESC, o.id DESC LIMIT 1) last ON true
                     WHERE c.workflow <> 'closed'
                       AND (last.basis IS NULL OR (last.basis = 'unresolved' AND (
                            EXISTS (SELECT 1 FROM axiom.policy_versions p WHERE p.kind = 'ownership'
                                       AND p.status = 'published' AND p.published_at > last.created_at)
                         OR EXISTS (SELECT 1 FROM axiom.case_occurrence_links l
                                      JOIN axiom.finding_occurrences fo ON fo.id = l.occurrence_id
                                      JOIN axiom.asset_versions av ON av.id = fo.asset_version_id
                                      JOIN axiom.business_context_versions b ON b.asset_id = av.asset_id
                                     WHERE l.case_id = c.id AND l.unlinked_at IS NULL
                                       AND b.recorded_at > last.created_at))))
                     ORDER BY c.created_at LIMIT 500""").fetchall():
                row = route(svc, c["id"])
                routed.append({"case_id": str(c["id"]), "basis": row["basis"]})
        return Done({"routed": routed})
