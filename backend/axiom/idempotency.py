"""API idempotency keys (API-07, Data and Access Design S 9).

Uniqueness is (tenant, principal, endpoint, key). The request digest covers the endpoint's path parameters and
body, so the same key with different arguments or on a different resource is rejected (422
``idempotency_key_reused``). Arguments are compared by meaning, not spelling: a timestamp is digested as the
instant it names, in UTC, so a retry that writes the same instant with another offset replays the stored response.

The key row is inserted first, inside the same transaction as the command:
* a concurrent request with the same key blocks on the primary key until the first commits, then replays its
  stored response (or is rejected if its arguments differ);
* if the command fails, its transaction rolls back and the key is free again, so a failed request can be retried;
* committed rows are always ``completed``: the row is updated with the response before commit.
Retention: rows carry ``expires_at`` (7 days); cleanup of expired rows is not built yet.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from .db import TenantContext
from .errors import ValidationFailed

_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
RETENTION = "7 days"


class IdempotencyKeyReused(ValidationFailed):
    code = "idempotency_key_reused"


def canonical(value: Any) -> Any:
    """Timezone-aware datetimes become UTC ISO strings; containers are walked; everything else is left alone."""
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical(v) for v in value]
    return value


def request_digest(endpoint: str, params: dict[str, Any], body: Any) -> str:
    doc = json.dumps({"endpoint": endpoint, "params": params, "body": canonical(body)}, sort_keys=True,
                     separators=(",", ":"), default=str)
    return hashlib.sha256(doc.encode()).hexdigest()


def run(conn: psycopg.Connection, ctx: TenantContext, *, endpoint: str, key: str, digest: str,
        fn: Callable[[], Any], status: int = 200) -> tuple[int, Any, bool]:
    """Run ``fn`` at most once per key. Returns (status, body, replayed)."""
    if not _KEY.match(key):
        raise ValidationFailed("Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:-]")
    inserted = conn.execute(
        f"""INSERT INTO axiom.idempotency_keys(tenant_id, principal_id, endpoint, key, request_digest, status, expires_at)
            VALUES (%s, %s, %s, %s, %s, 'in_progress', clock_timestamp() + interval '{RETENTION}')
            ON CONFLICT DO NOTHING RETURNING key""",
        (ctx.tenant_id, ctx.principal_id, endpoint, key, digest)).fetchone()
    if inserted is None:
        row = conn.execute(
            """SELECT * FROM axiom.idempotency_keys WHERE principal_id = %s AND endpoint = %s AND key = %s""",
            (ctx.principal_id, endpoint, key)).fetchone()
        if row["request_digest"] != digest:
            raise IdempotencyKeyReused("this Idempotency-Key was used with different arguments",
                                       details={"endpoint": endpoint})
        return row["response_status"], row["response_body"], True
    body = fn()
    conn.execute(
        """UPDATE axiom.idempotency_keys SET status = 'completed', response_status = %s, response_body = %s
            WHERE principal_id = %s AND endpoint = %s AND key = %s""",
        (status, Jsonb(body), ctx.principal_id, endpoint, key))
    return status, body, False
