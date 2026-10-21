from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Grant:
    tenant_id: str
    principal_id: str
    permission: str
    scope_id: str
    expires_at: datetime
    revoked: bool = False


def require_permission(grants: tuple[Grant, ...], *, tenant_id: str,
                       principal_id: str, permission: str, scope_id: str,
                       now: datetime) -> None:
    """Exact scopes only. Hierarchy and membership checks belong to the service layer."""
    if now.tzinfo is None:
        raise ValueError('timezone-aware time required')
    if any(g.tenant_id == tenant_id and g.principal_id == principal_id
           and g.permission == permission and g.scope_id == scope_id
           and not g.revoked and g.expires_at > now for g in grants):
        return
    raise PermissionError('permission denied')
