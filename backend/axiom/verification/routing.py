"""Which reported changes get an automated check, and where it is sent (ADR 0014)."""
from __future__ import annotations

from uuid import UUID

from ..access import Authorizer

KIND = "case.verification_check"
ADAPTER = "verification_check"


def covering_connection(conn, authz: Authorizer, scope_id: UUID) -> dict | None:
    """The active check connection nearest to the case scope (the scope itself, then its ancestors)."""
    lineage = list(authz.scope_lineage(scope_id))
    return conn.execute(
        """SELECT * FROM axiom.connections WHERE adapter = %s AND status = 'active' AND scope_id = ANY(%s)
            ORDER BY array_position(%s::uuid[], scope_id), created_at, id LIMIT 1""",
        (ADAPTER, lineage, lineage)).fetchone()
