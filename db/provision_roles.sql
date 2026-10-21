-- Cluster-level role provisioning for Axiom.
--
-- Run once per PostgreSQL cluster by a cluster administrator (not by the
-- application). Roles are cluster-global, which is why they are NOT created
-- inside per-database migrations (see docs/adr/0003-database-roles-and-migrations.md).
-- Idempotent: safe to re-run. Passwords for LOGIN roles are supplied as psql
-- variables and never stored in this file:
--
--   psql -v ON_ERROR_STOP=1 \
--        -v migrator_password=... -v app_password=... -v relay_password=... \
--        -v admin_cli_password=... \
--        -f db/provision_roles.sql
--
-- Group roles (NOLOGIN) carry privileges. LOGIN roles are members of exactly
-- one group role so that runtime identities never own objects, are never
-- superusers and never have BYPASSRLS.

\set ON_ERROR_STOP on

SELECT
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_owner')   AS need_owner,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_runtime') AS need_runtime,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_authn')   AS need_authn,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_relay')   AS need_relay,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_migrator') AS need_migrator,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_app')      AS need_app,
  NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_relay_app') AS need_relay_app
\gset

-- Owns schemas, tables and functions. Never used by the running application.
\if :need_owner
CREATE ROLE axiom_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
-- Privileges of the API and workers. Subject to forced row-level security.
\if :need_runtime
CREATE ROLE axiom_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
-- Owns the narrow SECURITY DEFINER authentication lookup functions.
\if :need_authn
CREATE ROLE axiom_authn NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
-- Transactional outbox relay: reads and marks outbox rows across tenants, nothing else.
\if :need_relay
CREATE ROLE axiom_relay NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif

-- Installation provisioning tooling: create tenants, principals and bootstrap
-- memberships/role bindings. Insert-mostly; no read access to tenant evidence.
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_provisioner') AS need_provisioner,
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axiom_admin_cli') AS need_admin_cli
\gset
\if :need_provisioner
CREATE ROLE axiom_provisioner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
\if :need_admin_cli
CREATE ROLE axiom_admin_cli LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif

\if :need_migrator
CREATE ROLE axiom_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
\if :need_app
CREATE ROLE axiom_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif
\if :need_relay_app
CREATE ROLE axiom_relay_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
\endif

ALTER ROLE axiom_migrator PASSWORD :'migrator_password';
ALTER ROLE axiom_app PASSWORD :'app_password';
ALTER ROLE axiom_relay_app PASSWORD :'relay_password';
ALTER ROLE axiom_admin_cli PASSWORD :'admin_cli_password';
GRANT axiom_provisioner TO axiom_admin_cli WITH INHERIT TRUE, SET FALSE;

-- The migrator acts as axiom_owner explicitly (SET ROLE) rather than inheriting it.
GRANT axiom_owner TO axiom_migrator WITH INHERIT FALSE, SET TRUE;
-- axiom_owner must be able to hand function ownership to axiom_authn during migration.
GRANT axiom_authn TO axiom_owner WITH INHERIT FALSE, SET TRUE;
GRANT axiom_runtime TO axiom_app WITH INHERIT TRUE, SET FALSE;
GRANT axiom_relay TO axiom_relay_app WITH INHERIT TRUE, SET FALSE;

-- Assert: runtime identities can never reach the owner role, and no platform
-- role is a superuser or has BYPASSRLS.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['axiom_app', 'axiom_relay_app', 'axiom_admin_cli'] LOOP
    IF pg_has_role(r, 'axiom_owner', 'MEMBER') THEN
      RAISE EXCEPTION 'role % must not be a member of axiom_owner', r;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'axiom\_%' AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'platform roles must not be superuser or BYPASSRLS';
  END IF;
END $$;
