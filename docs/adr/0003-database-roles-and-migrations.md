# ADR 0003: Database roles and migrations

Status: accepted (2026-10-22)

## Context
The supplied migration created `axiom_runtime` inside a per-database migration. Roles are cluster-global, so a second
database in the same cluster failed (observed). There was no migration ledger and no separation between owner and
runtime identities beyond one group role.

## Decision
* **Role provisioning** is a separate, idempotent, cluster-level script (`db/provision_roles.sql`) run by a cluster
  administrator. It creates NOLOGIN group roles and LOGIN roles, sets passwords from psql variables (never stored in
  the file), and asserts that no platform role is superuser or BYPASSRLS and no runtime login can reach the owner.

| Role | Kind | Purpose |
|---|---|---|
| axiom_owner | group | Owns schemas, tables, functions. Never used by the running application. |
| axiom_runtime | group | API and workers. Forced RLS applies. Column-level UPDATE grants only where commands need them. |
| axiom_authn | group | Owns `axiom_auth` SECURITY DEFINER lookups (principal, membership, tenant selection). Nobody logs in as it. |
| axiom_relay | group | Outbox relay: read/mark outbox rows across tenants; nothing else. |
| axiom_provisioner | group | Installation tooling: create tenants, principals, bootstrap memberships; no case, evidence or audit reads. |
| axiom_migrator | login | Member of axiom_owner with SET only (no INHERIT); runs migrations via `SET ROLE axiom_owner`. |
| axiom_app / axiom_relay_app / axiom_admin_cli | login | Members of runtime / relay / provisioner respectively. |

* **Migrations** live in `backend/axiom/migrations/NNNN_name.sql` and are applied by `python -m axiom.migrate`,
  each in one transaction, under an advisory lock, recorded in `axiom_meta.schema_migrations` with SHA-256. Editing an
  applied migration is a hard error; fix forward with a new migration. Unknown applied versions are also an error.
* Backup and operations roles are still to be defined (OPS-06).

## Consequences
Multiple databases per cluster work (verified: two databases in one fresh cluster). Upgrades are forward-only;
rolling back binaries does not imply schema downgrade (Plan 11).
