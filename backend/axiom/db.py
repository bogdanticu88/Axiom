"""PostgreSQL access with transaction-scoped tenant context.

Every tenant-scoped unit of work runs in one explicit transaction that first
calls axiom.bind_context(tenant, principal). The binding is transaction-local and
tied to the transaction itself (see migration 0001), so a pooled connection
never carries one tenant's context into another request. Pool check-in also
resets session state as a second line of defence.

This module never decides *whether* a principal may enter a tenant; callers
pass a TenantContext produced by axiom.auth after membership validation.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .errors import ConfigurationError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TenantContext:
    """Authorised tenant selection for one request or job. Construct only after validation."""
    tenant_id: UUID
    principal_id: UUID
    principal_kind: str          # 'human' | 'workload'
    correlation_id: str


def _reset(conn: psycopg.Connection) -> None:
    # RESET ALL clears any session-level custom settings (including axiom.ctx)
    # that buggy code might have set with is_local=false. Commit so the pool sees
    # an idle connection (otherwise it discards the connection instead of reusing it).
    conn.execute("RESET ALL")
    conn.commit()


class Database:
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10, name: str = "runtime"):
        self.pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, open=False, name=name,
            reset=_reset, check=ConnectionPool.check_connection,
            kwargs={"autocommit": False, "row_factory": dict_row},
        )

    def open(self) -> None:
        self.pool.open(wait=True, timeout=30)

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def tenant_tx(self, ctx: TenantContext) -> Iterator[psycopg.Connection]:
        """One transaction bound to exactly one tenant. Commits on success, rolls back on error."""
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT axiom.bind_context(%s, %s)", (ctx.tenant_id, ctx.principal_id))
                yield conn

    @contextmanager
    def unbound_tx(self) -> Iterator[psycopg.Connection]:
        """Transaction without tenant context: authentication lookups and security events only."""
        with self.pool.connection() as conn:
            with conn.transaction():
                yield conn

    def verify_runtime_role(self) -> None:
        """Refuse to run with an identity that would defeat row-level security."""
        with self.unbound_tx() as conn:
            row = conn.execute(
                """
                SELECT current_user AS role, r.rolsuper, r.rolbypassrls,
                       pg_has_role(current_user, 'axiom_owner', 'MEMBER') AS owner_member,
                       pg_has_role(current_user, 'axiom_runtime', 'USAGE') AS runtime_privs,
                       EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                WHERE n.nspname IN ('axiom', 'axiom_auth', 'axiom_meta')
                                  AND pg_has_role(current_user, c.relowner, 'MEMBER')) AS owns_objects
                  FROM pg_roles r WHERE r.rolname = current_user
                """).fetchone()
        problems = []
        if row["rolsuper"]:
            problems.append("is superuser")
        if row["rolbypassrls"]:
            problems.append("has BYPASSRLS")
        if row["owner_member"]:
            problems.append("is a member of axiom_owner")
        if row["owns_objects"]:
            problems.append("owns platform objects")
        if not row["runtime_privs"]:
            problems.append("lacks axiom_runtime privileges")
        if problems:
            raise ConfigurationError(f"unsafe runtime database role {row['role']}: {', '.join(problems)}")
