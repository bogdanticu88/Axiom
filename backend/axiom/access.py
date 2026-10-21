"""Scoped role-based authorisation.

Pure evaluation (``evaluate``) is separated from loading (``Authorizer``) so the
rules can be unit-tested exhaustively and the loader can be tested against
PostgreSQL. Rules:

* A binding applies only to its tenant and principal, between valid_from and
  valid_until, and only while not revoked.
* A binding at scope S covers S and every descendant of S (never ancestors or
  siblings).
* The role must contain the permission in the role catalogue.
* Administration does not imply evidence, risk or approval authority: those
  permissions exist only in roles that must be granted explicitly.

Authority is re-evaluated from current rows in every transaction; nothing is
cached across requests, so revocation takes effect on the next request.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

from .db import TenantContext
from .errors import Forbidden, NotFound

PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3, "urgent": 4}


def priority_rank(priority: str) -> int:
    """Unknown ('pending') priority is treated as the most severe (conservative)."""
    return PRIORITY_RANK.get(priority, PRIORITY_RANK["urgent"])


@dataclass(frozen=True)
class RoleBinding:
    id: UUID
    tenant_id: UUID
    principal_id: UUID
    role_id: str
    scope_id: UUID
    valid_from: datetime
    valid_until: datetime | None
    revoked_at: datetime | None
    emergency: bool = False

    def active_at(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("timezone-aware time required")
        return (self.revoked_at is None and self.valid_from <= now
                and (self.valid_until is None or self.valid_until > now))


@dataclass(frozen=True)
class Authority:
    """What authorised a decision; stored with decisions for later reconstruction."""
    permission: str
    scope_id: UUID
    binding_ids: tuple[UUID, ...]
    roles: tuple[str, ...]
    evaluated_at: datetime

    def as_json(self) -> dict:
        return {"permission": self.permission, "scope_id": str(self.scope_id),
                "binding_ids": [str(b) for b in self.binding_ids], "roles": list(self.roles),
                "evaluated_at": self.evaluated_at.isoformat()}


class PermissionDenied(Forbidden):
    code = "permission_denied"


def evaluate(bindings: Iterable[RoleBinding], role_permissions: Mapping[str, frozenset[str]], *,
             tenant_id: UUID, principal_id: UUID, permission: str,
             scope_lineage: tuple[UUID, ...], now: datetime) -> Authority:
    """Return the authority for ``permission`` at the first scope of ``scope_lineage``.

    ``scope_lineage`` is the target scope followed by its ancestors up to the root.
    """
    if not scope_lineage:
        raise ValueError("scope lineage required")
    covering = set(scope_lineage)
    matched = [b for b in bindings
               if b.tenant_id == tenant_id and b.principal_id == principal_id
               and b.active_at(now) and b.scope_id in covering
               and permission in role_permissions.get(b.role_id, frozenset())]
    if not matched:
        raise PermissionDenied("permission denied")
    return Authority(permission, scope_lineage[0], tuple(sorted(b.id for b in matched)),
                     tuple(sorted({b.role_id for b in matched})), now)


class Authorizer:
    """Loads authority for one principal inside one tenant-bound transaction."""

    def __init__(self, conn: psycopg.Connection, ctx: TenantContext):
        self._conn = conn
        self._ctx = ctx
        self._role_permissions: dict[str, frozenset[str]] | None = None
        self._bindings: dict[UUID, list[RoleBinding]] = {}
        self._lineage: dict[UUID, tuple[UUID, ...]] = {}

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def now(self) -> datetime:
        return self._conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]

    def role_permissions(self) -> dict[str, frozenset[str]]:
        if self._role_permissions is None:
            perms: dict[str, set[str]] = {}
            for row in self._conn.execute(
                    "SELECT rp.role_id, rp.permission FROM axiom.role_permissions rp"
                    " JOIN axiom.roles r ON r.id = rp.role_id"):
                perms.setdefault(row["role_id"], set()).add(row["permission"])
            self._role_permissions = {k: frozenset(v) for k, v in perms.items()}
        return self._role_permissions

    def bindings_for(self, principal_id: UUID) -> list[RoleBinding]:
        if principal_id not in self._bindings:
            rows = self._conn.execute(
                """SELECT b.id, b.tenant_id, b.principal_id, b.role_id, b.scope_id, b.valid_from,
                          b.valid_until, b.revoked_at, b.emergency
                     FROM axiom.role_bindings b
                     JOIN axiom.memberships m ON m.tenant_id = b.tenant_id AND m.principal_id = b.principal_id
                    WHERE b.principal_id = %s AND m.status = 'active'
                      AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp())""",
                (principal_id,))
            self._bindings[principal_id] = [RoleBinding(**r) for r in rows]
        return self._bindings[principal_id]

    def scope_lineage(self, scope_id: UUID) -> tuple[UUID, ...]:
        if scope_id not in self._lineage:
            rows = self._conn.execute(
                """WITH RECURSIVE up(id, parent_id, depth) AS (
                       SELECT id, parent_id, 0 FROM axiom.scopes WHERE id = %s
                       UNION ALL
                       SELECT s.id, s.parent_id, up.depth + 1 FROM axiom.scopes s
                         JOIN up ON s.id = up.parent_id WHERE up.depth < 64)
                   SELECT id FROM up ORDER BY depth""", (scope_id,)).fetchall()
            if not rows:
                raise NotFound("scope not found")
            self._lineage[scope_id] = tuple(r["id"] for r in rows)
        return self._lineage[scope_id]

    def require(self, permission: str, scope_id: UUID, *, principal_id: UUID | None = None) -> Authority:
        principal = principal_id or self._ctx.principal_id
        return evaluate(self.bindings_for(principal), self.role_permissions(),
                        tenant_id=self._ctx.tenant_id, principal_id=principal, permission=permission,
                        scope_lineage=self.scope_lineage(scope_id), now=self.now())

    def has(self, permission: str, scope_id: UUID, *, principal_id: UUID | None = None) -> bool:
        try:
            self.require(permission, scope_id, principal_id=principal_id)
            return True
        except PermissionDenied:
            return False

    def readable_scopes(self, permission: str) -> list[UUID]:
        """Scopes (with descendants) at which the caller holds ``permission``; for list filtering."""
        now = self.now()
        perms = self.role_permissions()
        return sorted({b.scope_id for b in self.bindings_for(self._ctx.principal_id)
                       if b.active_at(now) and permission in perms.get(b.role_id, frozenset())})
