"""Installation provisioning (runs as axiom_admin_cli -> axiom_provisioner).

Creates installations, tenants (with a root scope and a per-tenant system
workload principal), principals with federated identities, memberships, and
bootstrap role bindings. The provisioning role can insert these rows but has
no access to cases, evidence, decisions or audit history.

Bootstrap bindings have granted_by = NULL and are audited as system actions.
Use them only to create the first tenant administrator; subsequent grants go
through the tenant administration API so delegation rules apply.

CLI:
  python -m axiom.provisioning --dsn "$AXIOM_ADMIN_DSN" create-tenant --slug acme --name "Acme"
"""
from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


@dataclass(frozen=True)
class TenantBootstrap:
    tenant_id: UUID
    root_scope_id: UUID
    system_principal_id: UUID


class Provisioner:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, row_factory=dict_row)

    @staticmethod
    def _audit(conn, tenant_id: UUID, action: str, resource_type: str, resource_id, detail: dict) -> None:
        conn.execute(
            """INSERT INTO axiom.audit_events(tenant_id, id, actor_kind, correlation_id, action, resource_type,
                   resource_id, outcome, detail) VALUES (%s, %s, 'system', %s, %s, %s, %s, 'committed', %s)""",
            (tenant_id, uuid.uuid4(), f"provisioning:{uuid.uuid4()}", action, resource_type, str(resource_id),
             Jsonb({**detail, "via": "provisioning"})))

    def ensure_installation(self, profile: str, region: str | None = None) -> UUID:
        with self._connect() as conn:
            row = conn.execute("SELECT id, deployment_profile FROM axiom.installations").fetchone()
            if row:
                if row["deployment_profile"] != profile:
                    raise RuntimeError(f"installation already exists with profile {row['deployment_profile']}")
                return row["id"]
            installation_id = uuid.uuid4()
            conn.execute("INSERT INTO axiom.installations(id, deployment_profile, region) VALUES (%s, %s, %s)",
                         (installation_id, profile, region))
            return installation_id

    def create_tenant(self, installation_id: UUID, slug: str, display_name: str) -> TenantBootstrap:
        tenant_id, scope_id, system_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO axiom.tenants(id, installation_id, slug, display_name, status)
                   VALUES (%s, %s, %s, %s, 'active')""", (tenant_id, installation_id, slug, display_name))
            conn.execute("INSERT INTO axiom.scopes(tenant_id, id, kind, name) VALUES (%s, %s, 'tenant_root', %s)",
                         (tenant_id, scope_id, display_name))
            conn.execute("INSERT INTO axiom.principals(id, kind, display_name, status) VALUES (%s, 'workload', %s, 'active')",
                         (system_id, f"system:{slug}"))
            conn.execute("INSERT INTO axiom.memberships(tenant_id, id, principal_id, status) VALUES (%s, %s, %s, 'active')",
                         (tenant_id, uuid.uuid4(), system_id))
            conn.execute("UPDATE axiom.tenants SET system_principal_id = %s, record_version = record_version + 1 "
                         "WHERE id = %s", (system_id, tenant_id))
            # The system principal's authority is an explicit, auditable role binding.
            conn.execute(
                """INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by, reason)
                   VALUES (%s, %s, %s, 'ingestion_worker', %s, NULL, 'tenant system principal: ingestion runs')""",
                (tenant_id, uuid.uuid4(), system_id, scope_id))
            self._audit(conn, tenant_id, "tenant.create", "tenant", tenant_id,
                        {"slug": slug, "root_scope_id": str(scope_id), "system_principal_id": str(system_id)})
        return TenantBootstrap(tenant_id, scope_id, system_id)

    def create_verification_identity(self, tenant_id: UUID, scope_id: UUID | None = None) -> UUID:
        """Create the tenant's verification identity (ADR 0014): a workload principal, separate from the system
        principal, bound to the verification_worker role at ``scope_id`` (default: the tenant root). Refuses when the
        tenant already has one. Its authority is withdrawn like any other: revoke the binding or suspend the
        membership."""
        principal_id = uuid.uuid4()
        with self._connect() as conn:
            tenant = conn.execute("SELECT slug, verification_principal_id FROM axiom.tenants WHERE id = %s FOR UPDATE",
                                  (tenant_id,)).fetchone()
            if tenant is None:
                raise RuntimeError("tenant not found")
            if tenant["verification_principal_id"] is not None:
                raise RuntimeError("tenant already has a verification identity")
            if scope_id is None:
                scope_id = conn.execute("SELECT id FROM axiom.scopes WHERE tenant_id = %s AND kind = 'tenant_root'",
                                        (tenant_id,)).fetchone()["id"]
            conn.execute("INSERT INTO axiom.principals(id, kind, display_name, status) VALUES (%s, 'workload', %s, 'active')",
                         (principal_id, f"verification:{tenant['slug']}"))
            conn.execute("INSERT INTO axiom.memberships(tenant_id, id, principal_id, status) VALUES (%s, %s, %s, 'active')",
                         (tenant_id, uuid.uuid4(), principal_id))
            binding_id = uuid.uuid4()
            conn.execute(
                """INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by, reason)
                   VALUES (%s, %s, %s, 'verification_worker', %s, NULL, 'tenant verification identity')""",
                (tenant_id, binding_id, principal_id, scope_id))
            conn.execute("UPDATE axiom.tenants SET verification_principal_id = %s WHERE id = %s", (principal_id, tenant_id))
            self._audit(conn, tenant_id, "tenant.verification_identity", "principal", principal_id,
                        {"binding_id": str(binding_id), "scope_id": str(scope_id)})
        return principal_id

    def create_scope(self, tenant_id: UUID, parent_id: UUID, kind: str, name: str) -> UUID:
        scope_id = uuid.uuid4()
        with self._connect() as conn:
            conn.execute("INSERT INTO axiom.scopes(tenant_id, id, kind, parent_id, name) VALUES (%s, %s, %s, %s, %s)",
                         (tenant_id, scope_id, kind, parent_id, name))
            self._audit(conn, tenant_id, "scope.create", "scope", scope_id, {"parent_id": str(parent_id)})
        return scope_id

    def set_tenant_status(self, tenant_id: UUID, status: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE axiom.tenants SET status = %s, record_version = record_version + 1 WHERE id = %s",
                         (status, tenant_id))
            self._audit(conn, tenant_id, "tenant.status", "tenant", tenant_id, {"status": status})

    def ensure_identity_provider(self, issuer: str, audience: str, tenant_id: UUID | None = None) -> UUID:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM axiom.identity_providers WHERE issuer = %s AND audience = %s",
                               (issuer, audience)).fetchone()
            if row:
                return row["id"]
            provider_id = uuid.uuid4()
            conn.execute("""INSERT INTO axiom.identity_providers(id, tenant_id, issuer, audience, status)
                            VALUES (%s, %s, %s, %s, 'active')""", (provider_id, tenant_id, issuer, audience))
            return provider_id

    def create_principal(self, display_name: str, *, provider_id: UUID | None = None, subject: str | None = None,
                         kind: str = "human") -> UUID:
        principal_id = uuid.uuid4()
        with self._connect() as conn:
            conn.execute("INSERT INTO axiom.principals(id, kind, display_name, status) VALUES (%s, %s, %s, 'active')",
                         (principal_id, kind, display_name))
            if provider_id is not None:
                conn.execute("INSERT INTO axiom.federated_identities(provider_id, subject, principal_id) VALUES (%s, %s, %s)",
                             (provider_id, subject, principal_id))
        return principal_id

    def add_membership(self, tenant_id: UUID, principal_id: UUID) -> UUID:
        membership_id = uuid.uuid4()
        with self._connect() as conn:
            conn.execute("INSERT INTO axiom.memberships(tenant_id, id, principal_id, status) VALUES (%s, %s, %s, 'active')",
                         (tenant_id, membership_id, principal_id))
            self._audit(conn, tenant_id, "membership.create", "membership", membership_id,
                        {"principal_id": str(principal_id)})
        return membership_id

    def bootstrap_role(self, tenant_id: UUID, principal_id: UUID, role_id: str, scope_id: UUID, reason: str) -> UUID:
        binding_id = uuid.uuid4()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by, reason)
                   VALUES (%s, %s, %s, %s, %s, NULL, %s)""",
                (tenant_id, binding_id, principal_id, role_id, scope_id, reason))
            self._audit(conn, tenant_id, "role.bootstrap", "role_binding", binding_id,
                        {"principal_id": str(principal_id), "role": role_id, "scope_id": str(scope_id)})
        return binding_id

    def grant_installation_role(self, principal_id: UUID, role: str = "installation_operator") -> UUID:
        binding_id = uuid.uuid4()
        with self._connect() as conn:
            conn.execute("INSERT INTO axiom.installation_role_bindings(id, principal_id, role) VALUES (%s, %s, %s)",
                         (binding_id, principal_id, role))
        return binding_id

    def recovery_status(self, witness=None) -> dict:
        """Current database fingerprint, whether it is acknowledged, effect watermarks, and effects whose outcome
        is uncertain."""
        from .jobs.witness import check, database_watermark
        with self._connect() as conn:
            db_mark = database_watermark(conn)
            witness_problem = check(conn, witness)
            fp = conn.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]
            ack = conn.execute("SELECT * FROM axiom.recovery_acknowledgements WHERE fingerprint = %s", (fp,)).fetchone()
            pending = conn.execute(
                """SELECT count(*) AS n FROM axiom.effect_intents
                    WHERE state IN ('prepared', 'executing', 'unknown') AND db_fingerprint <> %s""", (fp,)).fetchone()
        return {"fingerprint": fp, "acknowledged": ack is not None, "uncertain_effects_from_other_fingerprints":
                pending["n"], "database_watermark": db_mark,
                "witness_high_water": witness.high_water() if witness is not None else None,
                "witness_problem": witness_problem}

    def acknowledge_recovery(self, acknowledged_by: str, note: str, witness=None) -> str:
        """Record that an operator has reconciled external effects after a restore (ADR 0006, ADR 0010).

        With a witness, the effect watermark sequence is moved past the witness high-water mark (so the database
        is no longer "behind"), and an empty witness is seeded from the database."""
        from .jobs.witness import database_watermark
        if not note.strip() or not acknowledged_by.strip():
            raise ValueError("acknowledged_by and a note describing the reconciliation are required")
        with self._connect() as conn:
            if witness is not None:
                external = witness.high_water()
                db_mark = database_watermark(conn)
                if external is not None and external > db_mark:
                    conn.execute("SELECT setval('axiom.effect_watermark_seq', %s, true)", (external,))
                elif external is None and db_mark > 0:
                    witness.advance(db_mark)
            fp = conn.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]
            # Always a new row: a rollback that keeps the fingerprint is acknowledged again. Acknowledging never
            # clears jobs; each job that predates this row needs its own reconciliation before any effect.
            conn.execute("""INSERT INTO axiom.recovery_acknowledgements(fingerprint, acknowledged_by, note)
                            VALUES (%s, %s, %s)""", (fp, acknowledged_by, note))
        return fp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Installation provisioning")
    parser.add_argument("--dsn", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    inst = sub.add_parser("ensure-installation")
    inst.add_argument("--profile", choices=["shared", "dedicated"], required=True)
    inst.add_argument("--region")
    ten = sub.add_parser("create-tenant")
    ten.add_argument("--installation", required=True)
    ten.add_argument("--slug", required=True)
    ten.add_argument("--name", required=True)
    usr = sub.add_parser("create-user")
    usr.add_argument("--issuer", required=True)
    usr.add_argument("--audience", required=True)
    usr.add_argument("--subject", required=True)
    usr.add_argument("--name", required=True)
    mem = sub.add_parser("add-member")
    mem.add_argument("--tenant", required=True)
    mem.add_argument("--principal", required=True)
    rol = sub.add_parser("bootstrap-role")
    rol.add_argument("--tenant", required=True)
    rol.add_argument("--principal", required=True)
    rol.add_argument("--role", required=True)
    rol.add_argument("--scope", required=True)
    rol.add_argument("--reason", required=True)
    ver = sub.add_parser("create-verification-identity")
    ver.add_argument("--tenant", required=True)
    ver.add_argument("--scope")
    st = sub.add_parser("recovery-status")
    st.add_argument("--witness-dir")
    ack = sub.add_parser("acknowledge-recovery")
    ack.add_argument("--by", required=True)
    ack.add_argument("--note", required=True)
    ack.add_argument("--witness-dir")
    args = parser.parse_args(argv)
    p = Provisioner(args.dsn)
    if args.command == "ensure-installation":
        out = {"installation_id": str(p.ensure_installation(args.profile, args.region))}
    elif args.command == "create-tenant":
        b = p.create_tenant(UUID(args.installation), args.slug, args.name)
        out = {k: str(v) for k, v in b.__dict__.items()}
    elif args.command == "create-user":
        provider = p.ensure_identity_provider(args.issuer, args.audience)
        out = {"principal_id": str(p.create_principal(args.name, provider_id=provider, subject=args.subject))}
    elif args.command == "add-member":
        out = {"membership_id": str(p.add_membership(UUID(args.tenant), UUID(args.principal)))}
    elif args.command == "create-verification-identity":
        out = {"principal_id": str(p.create_verification_identity(
            UUID(args.tenant), UUID(args.scope) if args.scope else None))}
    elif args.command in ("recovery-status", "acknowledge-recovery"):
        from .jobs.witness import FileWitness
        witness = FileWitness(args.witness_dir, "operator-acknowledgement") if args.witness_dir else None
        if args.command == "recovery-status":
            out = p.recovery_status(witness)
        else:
            out = {"acknowledged_fingerprint": p.acknowledge_recovery(args.by, args.note, witness)}
    else:
        out = {"binding_id": str(p.bootstrap_role(UUID(args.tenant), UUID(args.principal), args.role,
                                                   UUID(args.scope), args.reason))}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
