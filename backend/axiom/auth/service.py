"""Principal resolution and tenant selection.

Implements steps 1-3 of the authorisation algorithm in the Data and Access
Design (section 12): validate the token, resolve an active principal, then
validate the explicit tenant selection against an active membership in an
active tenant. The client-supplied tenant selector is a *request*, never proof
of authority. Every request is re-authorised; there is no sticky tenant session.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from uuid import UUID

from ..db import Database, TenantContext
from ..errors import Forbidden, Unauthenticated
from .tokens import TokenVerifier, VerifiedIdentity


@dataclass(frozen=True)
class Actor:
    principal_id: UUID
    kind: str
    issuer: str
    subject: str


class Authenticator:
    def __init__(self, db: Database, verifier: TokenVerifier):
        self._db = db
        self._verifier = verifier

    def authenticate(self, bearer_token: str) -> Actor:
        identity: VerifiedIdentity = self._verifier.verify(bearer_token)
        with self._db.unbound_tx() as conn:
            row = conn.execute(
                "SELECT principal_id, principal_kind FROM axiom_auth.resolve_principal(%s, %s, %s)",
                (identity.issuer, identity.audience, identity.subject)).fetchone()
        if row is None:
            # Valid token, but no active platform principal: identity is not membership.
            raise Unauthenticated("identity is not provisioned for this installation")
        return Actor(row["principal_id"], row["principal_kind"], identity.issuer, identity.subject)

    def select_tenant(self, actor: Actor, selector: str | None, correlation_id: str) -> TenantContext:
        if not selector:
            raise Forbidden("tenant selection required", code="tenant_selection_required")
        with self._db.unbound_tx() as conn:
            row = conn.execute("SELECT tenant_id FROM axiom_auth.select_tenant(%s, %s)",
                               (actor.principal_id, selector[:128])).fetchone()
            if row is None:
                # Same response whether the tenant does not exist, is suspended, or the
                # principal is not a member; record the attempt without tenant data.
                conn.execute(
                    "INSERT INTO axiom.security_events(id, principal_id, requested_tenant, correlation_id,"
                    " event_type, reason_code) VALUES (%s, %s, %s, %s, 'tenant_selection', 'denied')",
                    (uuid.uuid4(), actor.principal_id, selector[:128], correlation_id))
        if row is None:
            raise Forbidden("tenant not available", code="tenant_not_available")
        return TenantContext(row["tenant_id"], actor.principal_id, actor.kind, correlation_id)

    def list_tenants(self, actor: Actor) -> list[dict]:
        with self._db.unbound_tx() as conn:
            return list(conn.execute("SELECT tenant_id, slug, display_name FROM axiom_auth.list_tenants(%s)",
                                     (actor.principal_id,)))

    def installation_roles(self, actor: Actor) -> list[str]:
        with self._db.unbound_tx() as conn:
            return [r["role"] for r in conn.execute(
                "SELECT role FROM axiom_auth.installation_roles(%s)", (actor.principal_id,))]
