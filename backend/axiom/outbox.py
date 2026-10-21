"""Transactional outbox and consumer inbox.

Producers call ``enqueue`` inside the same transaction as the state change, so
an event exists if and only if the change committed. The relay delivers at
least once using leases (FOR UPDATE SKIP LOCKED); consumers deduplicate with
``Inbox.first_delivery``. No exactly-once delivery is claimed.

The relay runs as axiom_relay_app, which can read and mark outbox rows across
tenants but has no access to any other table. Each delivered message carries
the tenant ID from its persisted row; consumers bind that tenant, never one
taken from a message body field.
"""
from __future__ import annotations

import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .db import Database, TenantContext


def enqueue(conn: psycopg.Connection, ctx: TenantContext, *, topic: str, aggregate_type: str,
            aggregate_id: UUID, payload: dict) -> UUID:
    message_id = uuid.uuid4()
    conn.execute(
        """INSERT INTO axiom.outbox(tenant_id, id, topic, aggregate_type, aggregate_id, payload)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (ctx.tenant_id, message_id, topic, aggregate_type, aggregate_id,
         Jsonb({**payload, "correlation_id": ctx.correlation_id})))
    return message_id


@dataclass(frozen=True)
class OutboxMessage:
    tenant_id: UUID
    id: UUID
    topic: str
    aggregate_type: str
    aggregate_id: UUID
    payload: dict
    attempts: int
    created_at: datetime


class Relay:
    def __init__(self, db: Database, *, worker_id: str | None = None, lease_seconds: int = 60,
                 max_backoff_seconds: int = 900):
        self._db = db
        self.worker_id = worker_id or f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}"
        self._lease = lease_seconds
        self._max_backoff = max_backoff_seconds

    def claim(self, limit: int = 50) -> list[OutboxMessage]:
        with self._db.unbound_tx() as conn:
            rows = conn.execute(
                """UPDATE axiom.outbox o
                      SET lease_owner = %(owner)s,
                          lease_expires_at = clock_timestamp() + make_interval(secs => %(lease)s),
                          attempts = o.attempts + 1
                     FROM (SELECT tenant_id, id FROM axiom.outbox
                            WHERE delivered_at IS NULL AND available_at <= clock_timestamp()
                              AND (lease_expires_at IS NULL OR lease_expires_at < clock_timestamp())
                            ORDER BY available_at, created_at
                            LIMIT %(limit)s
                            FOR UPDATE SKIP LOCKED) ready
                    WHERE o.tenant_id = ready.tenant_id AND o.id = ready.id
                RETURNING o.tenant_id, o.id, o.topic, o.aggregate_type, o.aggregate_id, o.payload,
                          o.attempts, o.created_at""",
                {"owner": self.worker_id, "lease": self._lease, "limit": limit}).fetchall()
        return [OutboxMessage(**r) for r in rows]

    def mark_delivered(self, message: OutboxMessage) -> bool:
        with self._db.unbound_tx() as conn:
            cur = conn.execute(
                """UPDATE axiom.outbox SET delivered_at = clock_timestamp(), lease_owner = NULL,
                          lease_expires_at = NULL, last_error = NULL
                    WHERE tenant_id = %s AND id = %s AND lease_owner = %s AND delivered_at IS NULL""",
                (message.tenant_id, message.id, self.worker_id))
            return cur.rowcount == 1

    def mark_failed(self, message: OutboxMessage, error: str) -> None:
        backoff = min(self._max_backoff, 2 ** min(message.attempts, 10))
        with self._db.unbound_tx() as conn:
            conn.execute(
                """UPDATE axiom.outbox SET lease_owner = NULL, lease_expires_at = NULL,
                          last_error = %s, available_at = clock_timestamp() + make_interval(secs => %s)
                    WHERE tenant_id = %s AND id = %s AND lease_owner = %s AND delivered_at IS NULL""",
                (error[:2000], backoff, message.tenant_id, message.id, self.worker_id))

    def run_once(self, handler: Callable[[OutboxMessage], None], limit: int = 50) -> tuple[int, int]:
        delivered = failed = 0
        for message in self.claim(limit):
            try:
                handler(message)
            except Exception as exc:  # noqa: BLE001 - recorded and retried with backoff
                self.mark_failed(message, f"{type(exc).__name__}: {exc}")
                failed += 1
            else:
                if self.mark_delivered(message):
                    delivered += 1
        return delivered, failed


class Inbox:
    """Consumer-side deduplication: process each message at most once per consumer *commit*."""

    @staticmethod
    def first_delivery(conn: psycopg.Connection, ctx: TenantContext, consumer: str, message_id: UUID) -> bool:
        row = conn.execute(
            """INSERT INTO axiom.inbox(tenant_id, consumer, message_id) VALUES (%s, %s, %s)
               ON CONFLICT DO NOTHING RETURNING message_id""",
            (ctx.tenant_id, consumer, message_id)).fetchone()
        return row is not None


def jsonb(value: dict) -> Jsonb:
    return Jsonb(value)
