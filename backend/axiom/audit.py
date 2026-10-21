"""Audit events.

``record`` writes inside the caller's transaction, so an audit failure aborts
the consequential change it describes (B12, A19). ``record_denial`` uses its
own short transaction because the denied command's transaction rolls back.
Audit detail must never contain tokens, secrets or raw evidence content.
"""
from __future__ import annotations

import logging
import uuid
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .db import Database, TenantContext

log = logging.getLogger(__name__)

_FORBIDDEN_DETAIL_KEYS = {"token", "authorization", "password", "secret", "credential", "api_key"}


def _sanitise(detail: dict | None) -> dict:
    if not detail:
        return {}
    clean = {}
    for key, value in detail.items():
        if any(f in key.lower() for f in _FORBIDDEN_DETAIL_KEYS):
            clean[key] = "[redacted]"
        else:
            clean[key] = value
    return clean


def record(conn: psycopg.Connection, ctx: TenantContext, *, action: str, resource_type: str,
           resource_id: object | None, outcome: str = "committed", reason_code: str | None = None,
           detail: dict | None = None) -> UUID:
    event_id = uuid.uuid4()
    conn.execute(
        """INSERT INTO axiom.audit_events(tenant_id, id, actor_principal_id, actor_kind, correlation_id,
               action, resource_type, resource_id, outcome, reason_code, detail)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (ctx.tenant_id, event_id, ctx.principal_id, ctx.principal_kind, ctx.correlation_id, action,
         resource_type, None if resource_id is None else str(resource_id), outcome, reason_code,
         Jsonb(_sanitise(detail))))
    return event_id


def record_denial(db: Database, ctx: TenantContext, *, action: str, resource_type: str,
                  resource_id: object | None, reason_code: str, detail: dict | None = None) -> None:
    """Best-effort durable record of a denied request inside the caller's tenant."""
    try:
        with db.tenant_tx(ctx) as conn:
            record(conn, ctx, action=action, resource_type=resource_type, resource_id=resource_id,
                   outcome="denied", reason_code=reason_code, detail=detail)
    except psycopg.Error:
        # Denial stands regardless; failure to audit a denial is logged for operators.
        log.exception("failed to record denial audit", extra={"correlation_id": ctx.correlation_id})
