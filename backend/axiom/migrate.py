"""Ledgered SQL migration runner.

Applies backend/migrations/NNNN_name.sql in order, each in its own transaction,
as the migration login role acting as axiom_owner (SET ROLE). Applied files are
recorded with their SHA-256; a changed checksum of an applied migration is a
hard error (fix forward with a new migration instead of editing history).

Usage:
    python -m axiom.migrate --dsn "$AXIOM_MIGRATOR_DSN" [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
_LOCK_KEY = 0x5650_4D49  # "VPMI": serialises concurrent migration runs

LEDGER_DDL = """
CREATE SCHEMA IF NOT EXISTS axiom_meta;
REVOKE ALL ON SCHEMA axiom_meta FROM PUBLIC;
CREATE TABLE IF NOT EXISTS axiom_meta.schema_migrations (
  version text PRIMARY KEY,
  filename text NOT NULL,
  sha256 text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  applied_by text NOT NULL DEFAULT session_user
);
"""


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path
    sha256: str

    @property
    def sql(self) -> str:
        return self.path.read_text(encoding="utf-8")


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    found: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = _NAME.match(path.name)
        if not match:
            raise MigrationError(f"unexpected migration filename: {path.name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        found.append(Migration(match.group(1), path, digest))
    versions = [m.version for m in found]
    if len(set(versions)) != len(versions):
        raise MigrationError("duplicate migration version numbers")
    return found


def apply(dsn: str, *, directory: Path = MIGRATIONS_DIR, dry_run: bool = False,
          owner_role: str = "axiom_owner") -> list[str]:
    """Apply pending migrations. Returns the versions applied (or pending, for dry runs)."""
    migrations = discover(directory)
    applied_now: list[str] = []
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"SET ROLE {psycopg.sql.Identifier(owner_role).as_string(conn)}")
        conn.execute("SELECT pg_advisory_lock(%s)", (_LOCK_KEY,))
        try:
            with conn.transaction():
                conn.execute(LEDGER_DDL)
            ledger = {row[0]: row[1] for row in
                      conn.execute("SELECT version, sha256 FROM axiom_meta.schema_migrations")}
            known = {m.version for m in migrations}
            unknown = sorted(set(ledger) - known)
            if unknown:
                raise MigrationError(f"database has migrations not present in this build: {unknown}")
            for migration in migrations:
                if migration.version in ledger:
                    if ledger[migration.version] != migration.sha256:
                        raise MigrationError(
                            f"checksum mismatch for applied migration {migration.path.name}; "
                            "applied migrations must not be edited")
                    continue
                applied_now.append(migration.version)
                if dry_run:
                    continue
                with conn.transaction():
                    try:
                        conn.execute(migration.sql)
                    except psycopg.Error as exc:
                        diag = exc.diag
                        raise MigrationError(
                            f"{migration.path.name}: {diag.message_primary} "
                            f"(sqlstate={diag.sqlstate}, context={diag.context!r}, "
                            f"position={diag.statement_position})") from exc
                    conn.execute(
                        "INSERT INTO axiom_meta.schema_migrations(version, filename, sha256) VALUES (%s, %s, %s)",
                        (migration.version, migration.path.name, migration.sha256))
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_KEY,))
    return applied_now


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dsn", required=True, help="migration role connection string")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        versions = apply(args.dsn, dry_run=args.dry_run)
    except MigrationError as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        return 2
    verb = "pending" if args.dry_run else "applied"
    print(f"{verb}: {', '.join(versions) if versions else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
