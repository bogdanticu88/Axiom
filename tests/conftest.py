"""Shared fixtures.

Database tests need a disposable cluster started by ``scripts/dev/test-db.sh start``,
which writes ``.env.test``. Each pytest session creates a fresh database, applies
the migrations through the real runner as axiom_migrator, and connects the
application as axiom_app (runtime role, RLS enforced). Each test provisions its own
tenants and principals with unique names, so tests do not share business rows.
"""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import psycopg
import pytest
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parent.parent


def _load_env() -> dict[str, str] | None:
    path = ROOT / ".env.test"
    if not path.exists():
        return None
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key] = value.strip().strip('"')
    return env


@dataclass(frozen=True)
class DbInfo:
    name: str
    admin_dsn: str
    migrator_dsn: str
    app_dsn: str
    relay_dsn: str
    admin_cli_dsn: str


@pytest.fixture(scope="session")
def dbinfo() -> Iterator[DbInfo]:
    env = _load_env()
    if env is None:
        pytest.skip("no .env.test; run scripts/dev/test-db.sh start")
    name = f"axiom_test_{uuid.uuid4().hex[:10]}"
    admin = env["AXIOM_TEST_ADMIN_DSN"]
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}" OWNER axiom_owner')
        conn.execute(f'REVOKE ALL ON DATABASE "{name}" FROM PUBLIC')
        conn.execute(f'GRANT CONNECT ON DATABASE "{name}" TO axiom_migrator, axiom_app, axiom_relay_app, axiom_admin_cli')
    base = f"host={env['AXIOM_TEST_HOST']} port={env['AXIOM_TEST_PORT']} dbname={name}"
    info = DbInfo(
        name=name,
        admin_dsn=admin.replace("dbname=postgres", f"dbname={name}"),
        migrator_dsn=f"{base} user=axiom_migrator password={env['AXIOM_TEST_MIGRATOR_PASSWORD']}",
        app_dsn=f"{base} user=axiom_app password={env['AXIOM_TEST_APP_PASSWORD']}",
        relay_dsn=f"{base} user=axiom_relay_app password={env['AXIOM_TEST_RELAY_PASSWORD']}",
        admin_cli_dsn=f"{base} user=axiom_admin_cli password={env['AXIOM_TEST_ADMIN_CLI_PASSWORD']}",
    )
    from axiom import migrate
    applied = migrate.apply(info.migrator_dsn)
    assert applied, "fresh database should apply migrations"
    yield info
    if os.environ.get("AXIOM_KEEP_TEST_DB") != "1":
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture(scope="session")
def db(dbinfo):
    from axiom.db import Database
    database = Database(dbinfo.app_dsn, min_size=1, max_size=8)
    database.open()
    yield database
    database.close()


@pytest.fixture(scope="session")
def relay_db(dbinfo):
    from axiom.db import Database
    database = Database(dbinfo.relay_dsn, min_size=1, max_size=2, name="relay")
    database.open()
    yield database
    database.close()


@pytest.fixture()
def admin_conn(dbinfo):
    """Superuser connection to the test database, for fault injection and inspection only."""
    with psycopg.connect(dbinfo.admin_dsn, autocommit=True, row_factory=dict_row) as conn:
        yield conn


# --------------------------------------------------------------------- tokens
@dataclass
class TokenIssuer:
    issuer: str
    audience: str
    private_key: object
    kid: str

    def jwks(self) -> dict:
        from jwt.algorithms import RSAAlgorithm
        jwk = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def token(self, subject: str, *, ttl: int = 300, **overrides) -> str:
        import jwt
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": self.audience, "sub": subject, "iat": now, "exp": now + ttl}
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": self.kid})


@pytest.fixture(scope="session")
def issuer() -> TokenIssuer:
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return TokenIssuer("https://idp.test.invalid/realms/axiom", "axiom-api", key, "test-key-1")


# ---------------------------------------------------------------------- world
@dataclass
class Tenant:
    id: UUID
    slug: str
    root: UUID
    project: UUID
    other_project: UUID
    system: UUID


@dataclass
class World:
    """Two tenants and a cast of principals. Names map to principal IDs."""
    a: Tenant
    b: Tenant
    people: dict[str, UUID] = field(default_factory=dict)
    subjects: dict[str, str] = field(default_factory=dict)

    def __getitem__(self, name: str) -> UUID:
        return self.people[name]


@pytest.fixture()
def world(dbinfo, issuer) -> World:
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    installation = p.ensure_installation("shared")
    provider = p.ensure_identity_provider(issuer.issuer, issuer.audience)
    suffix = uuid.uuid4().hex[:8]

    def tenant(label: str) -> Tenant:
        boot = p.create_tenant(installation, f"{label}-{suffix}", f"Tenant {label.upper()} {suffix}")
        project = p.create_scope(boot.tenant_id, boot.root_scope_id, "project", "payments")
        other = p.create_scope(boot.tenant_id, boot.root_scope_id, "project", "marketing")
        return Tenant(boot.tenant_id, f"{label}-{suffix}", boot.root_scope_id, project, other, boot.system_principal_id)

    w = World(tenant("a"), tenant("b"))

    def person(name: str, memberships: list[tuple[Tenant, list[tuple[str, str]]]]) -> None:
        subject = f"{name}-{suffix}"
        pid = p.create_principal(name, provider_id=provider, subject=subject)
        w.people[name], w.subjects[name] = pid, subject
        for t, roles in memberships:
            p.add_membership(t.id, pid)
            for role, where in roles:
                scope = {"root": t.root, "project": t.project, "other": t.other_project}[where]
                p.bootstrap_role(t.id, pid, role, scope, f"test fixture: {name} {role}")

    a, b = w.a, w.b
    person("analyst", [(a, [("analyst", "project")])])
    person("analyst2", [(a, [("analyst", "project")])])
    person("owner", [(a, [("remediation_owner", "project")])])
    person("approver", [(a, [("approver", "project")])])
    person("risk_owner", [(a, [("risk_owner", "project")])])
    person("viewer", [(a, [("viewer", "project")])])
    person("marketing_analyst", [(a, [("analyst", "other")])])
    person("admin", [(a, [("tenant_admin", "root")])])
    person("auditor", [(a, [("auditor", "root")])])
    person("consultant", [(a, [("analyst", "project")]), (b, [("analyst", "project")])])
    person("analyst_b", [(b, [("analyst", "project")])])
    person("outsider", [])
    pid = p.create_principal("operator", provider_id=provider, subject=f"operator-{suffix}")
    p.grant_installation_role(pid)
    w.people["operator"], w.subjects["operator"] = pid, f"operator-{suffix}"
    return w


@pytest.fixture()
def ctx_for(world):
    from axiom.db import TenantContext

    def make(name: str, tenant: str = "a") -> TenantContext:
        t = world.a if tenant == "a" else world.b
        if name == "system":
            return TenantContext(t.id, t.system, "workload", f"test-{uuid.uuid4()}")
        return TenantContext(t.id, world[name], "human", f"test-{uuid.uuid4()}")
    return make


@pytest.fixture()
def run(db):
    """Run ``fn(services)`` in one tenant-bound transaction as the given context."""
    from axiom.access import Authorizer
    from axiom.domains.assets.service import AssetService
    from axiom.domains.cases.service import CaseService
    from axiom.domains.tenancy.service import TenancyService

    @dataclass
    class Services:
        conn: psycopg.Connection
        authz: Authorizer
        cases: CaseService
        assets: AssetService
        tenancy: TenancyService

    def _run(ctx, fn):
        with db.tenant_tx(ctx) as conn:
            authz = Authorizer(conn, ctx)
            return fn(Services(conn, authz, CaseService(conn, ctx, authz), AssetService(conn, ctx, authz),
                               TenancyService(conn, ctx, authz)))
    return _run


@pytest.fixture()
def object_store(tmp_path):
    from axiom.domains.evidence.objectstore import FilesystemObjectStore
    return FilesystemObjectStore(tmp_path / "objects")


@pytest.fixture()
def evidence(db, object_store):
    from axiom.domains.evidence.service import EvidenceService
    return EvidenceService(db, object_store, max_bytes=10 * 1024 * 1024)


@pytest.fixture()
def upload(evidence):
    """Upload and finalise evidence; returns the record."""
    import hashlib

    def _upload(ctx, scope_id, content: bytes = b"scan output", *, classification="internal",
                declared_sha=None, finalise=True):
        rec = evidence.initiate(ctx, scope_id=scope_id, sha256=declared_sha or hashlib.sha256(content).hexdigest(),
                                size=len(content), media_type="text/plain", classification=classification,
                                filename="evidence.txt")
        evidence.upload(ctx, rec["id"], iter([content]))
        return evidence.finalise(ctx, rec["id"]) if finalise else rec
    return _upload


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
