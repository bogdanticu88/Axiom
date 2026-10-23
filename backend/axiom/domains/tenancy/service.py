"""Tenant administration: role assignment, revocation and delegation limits.

Delegation rules (Data and Access Design section 11):
* Assigning a role at scope S requires role.assign covering S.
* Nobody grants themselves anything (also a database CHECK).
* Tenant administration grants no evidence, risk or approval authority to the
  administrator; those come only from roles explicitly assigned by someone else.
* Emergency bindings must expire within 24 hours, need a reason, and emit an
  outbox event for retrospective review.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from uuid import UUID

import psycopg

from ... import audit, outbox
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, Forbidden, NotFound, ValidationFailed

MAX_EMERGENCY = timedelta(hours=24)


class TenancyService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    def _require_member(self, principal_id: UUID) -> None:
        row = self.conn.execute(
            """SELECT status FROM axiom.memberships WHERE principal_id = %s
                 AND (valid_until IS NULL OR valid_until > clock_timestamp())""", (principal_id,)).fetchone()
        if row is None or row["status"] != "active":
            raise NotFound("principal is not an active member of this tenant", code="member_not_found")

    def assign_role(self, *, principal_id: UUID, role_id: str, scope_id: UUID, reason: str,
                    valid_until: datetime | None = None, emergency: bool = False) -> dict:
        authority = self.authz.require("role.assign", scope_id)
        if principal_id == self.ctx.principal_id:
            raise Forbidden("principals cannot assign roles to themselves", code="self_grant")
        if not reason.strip():
            raise ValidationFailed("a reason is required")
        self._require_member(principal_id)
        role = self.conn.execute("SELECT id FROM axiom.roles WHERE id = %s", (role_id,)).fetchone()
        if role is None:
            raise NotFound("role not found", code="role_not_found")
        now = self.authz.now()
        if valid_until is not None and (valid_until.tzinfo is None or valid_until.utcoffset() is None):
            raise ValidationFailed("valid_until must carry a UTC offset")
        if valid_until is not None and valid_until <= now:
            raise ValidationFailed("valid_until must be in the future")
        if emergency and (valid_until is None or valid_until > now + MAX_EMERGENCY):
            raise ValidationFailed("emergency access must expire within 24 hours")
        binding_id = uuid.uuid4()
        row = self.conn.execute(
            """INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by, reason,
                   valid_until, emergency) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, binding_id, principal_id, role_id, scope_id, self.ctx.principal_id, reason,
             valid_until, emergency)).fetchone()
        audit.record(self.conn, self.ctx, action="role.assign", resource_type="role_binding",
                     resource_id=binding_id, detail={"principal_id": str(principal_id), "role": role_id,
                                                     "scope_id": str(scope_id), "emergency": emergency,
                                                     "authority": authority.as_json()})
        if emergency:
            outbox.enqueue(self.conn, self.ctx, topic="access.emergency_granted", aggregate_type="role_binding",
                           aggregate_id=binding_id, payload={"principal_id": str(principal_id),
                                                             "role": role_id, "requires_review": True})
        return row

    def revoke_role(self, *, binding_id: UUID, reason: str) -> dict:
        binding = self.conn.execute("SELECT * FROM axiom.role_bindings WHERE id = %s", (binding_id,)).fetchone()
        if binding is None:
            raise NotFound("role binding not found")
        authority = self.authz.require("role.assign", binding["scope_id"])
        if binding["revoked_at"] is not None:
            raise Conflict("role binding already revoked", code="already_revoked")
        row = self.conn.execute(
            """UPDATE axiom.role_bindings SET revoked_at = clock_timestamp(), revoked_by = %s
                WHERE id = %s AND revoked_at IS NULL RETURNING *""",
            (self.ctx.principal_id, binding_id)).fetchone()
        audit.record(self.conn, self.ctx, action="role.revoke", resource_type="role_binding",
                     resource_id=binding_id, detail={"reason": reason, "authority": authority.as_json()})
        return row

    def set_delegation_limit(self, *, principal_id: UUID, action_class: str, scope_id: UUID,
                             max_priority: str, max_duration_days: int) -> dict:
        authority = self.authz.require("role.assign", scope_id)
        if principal_id == self.ctx.principal_id:
            raise Forbidden("principals cannot set their own delegation limits", code="self_grant")
        self._require_member(principal_id)
        limit_id = uuid.uuid4()
        row = self.conn.execute(
            """INSERT INTO axiom.delegation_limits(tenant_id, id, principal_id, action_class, scope_id, max_priority,
                   max_duration_days, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, limit_id, principal_id, action_class, scope_id, max_priority, max_duration_days,
             self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="delegation_limit.set", resource_type="delegation_limit",
                     resource_id=limit_id, detail={"principal_id": str(principal_id), "action_class": action_class,
                                                   "max_priority": max_priority,
                                                   "max_duration_days": max_duration_days,
                                                   "authority": authority.as_json()})
        return row

    def suspend_membership(self, *, principal_id: UUID, reason: str) -> dict:
        root = self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()
        authority = self.authz.require("membership.manage", root["id"])
        if principal_id == self.ctx.principal_id:
            raise Forbidden("principals cannot suspend themselves", code="self_action")
        row = self.conn.execute(
            """UPDATE axiom.memberships SET status = 'suspended', record_version = record_version + 1
                WHERE principal_id = %s AND status = 'active' RETURNING *""", (principal_id,)).fetchone()
        if row is None:
            raise NotFound("active membership not found", code="member_not_found")
        audit.record(self.conn, self.ctx, action="membership.suspend", resource_type="membership",
                     resource_id=row["id"], detail={"reason": reason, "authority": authority.as_json()})
        return row
