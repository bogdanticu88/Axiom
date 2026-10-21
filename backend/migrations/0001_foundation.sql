-- 0001 Foundation: tenancy, identity, authorisation catalogue, audit, outbox/inbox, evidence.
--
-- Applied by backend/axiom/migrate.py as axiom_migrator with SET ROLE axiom_owner,
-- inside a single transaction. Roles are provisioned separately by
-- db/provision_roles.sql (cluster-global objects do not belong in per-database
-- migrations).
--
-- Isolation model (docs/adr/0002-tenant-isolation.md):
--   * Every tenant-owned table has tenant_id, composite keys (tenant_id, id)
--     and composite tenant-aware foreign keys.
--   * Row-level security is ENABLED and FORCED on every tenant-owned table.
--   * Tenant context is a transaction-local setting bound to the current
--     transaction (timestamp + backend pid). A session-level setting that
--     survives into a later transaction on a pooled connection is ignored.
--   * Context-based RLS is defence in depth. A compromised application that can
--     choose arbitrary tenant context is NOT contained by RLS alone.

CREATE SCHEMA axiom;
REVOKE ALL ON SCHEMA axiom FROM PUBLIC;
GRANT USAGE ON SCHEMA axiom TO axiom_runtime, axiom_authn, axiom_relay;

-- ---------------------------------------------------------------------------
-- Context helpers (not SECURITY DEFINER; they grant nothing by themselves)
-- ---------------------------------------------------------------------------
CREATE FUNCTION axiom.tx_marker() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT (extract(epoch FROM transaction_timestamp()) * 1000000)::bigint::text
         || ':' || pg_backend_pid()::text
$$;

CREATE FUNCTION axiom.context_part(p_index int) RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT CASE WHEN split_part(c, '|', 3) = axiom.tx_marker()
              THEN nullif(split_part(c, '|', p_index), '') END
  FROM (SELECT nullif(current_setting('axiom.ctx', true), '') AS c) s
$$;

CREATE FUNCTION axiom.current_tenant() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT axiom.context_part(1)::uuid $$;

CREATE FUNCTION axiom.current_principal() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT axiom.context_part(2)::uuid $$;

-- Binds tenant and principal context for the CURRENT TRANSACTION ONLY.
-- Called by the application after trusted authentication and authorisation.
-- Refuses to switch tenant inside a transaction that is already bound.
CREATE FUNCTION axiom.bind_context(p_tenant uuid, p_principal uuid) RETURNS void
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  existing uuid := axiom.current_tenant();
BEGIN
  IF p_tenant IS NULL OR p_principal IS NULL THEN
    RAISE EXCEPTION 'tenant and principal context are required' USING ERRCODE = '42501';
  END IF;
  IF existing IS NOT NULL AND existing <> p_tenant THEN
    RAISE EXCEPTION 'tenant context already bound in this transaction' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('axiom.ctx', p_tenant::text || '|' || p_principal::text || '|' || axiom.tx_marker(), true);
END
$$;

REVOKE ALL ON FUNCTION axiom.tx_marker(), axiom.context_part(int), axiom.current_tenant(),
  axiom.current_principal(), axiom.bind_context(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.tx_marker(), axiom.context_part(int), axiom.current_tenant(),
  axiom.current_principal() TO axiom_runtime, axiom_authn, axiom_relay;
GRANT EXECUTE ON FUNCTION axiom.bind_context(uuid, uuid) TO axiom_runtime;

-- Generic guard: append-only tables reject UPDATE and DELETE for every role,
-- including the owner. Retention deletion will use a dedicated, audited path.
CREATE FUNCTION axiom.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;

-- Generic guard: tenant_id and id are immutable.
CREATE FUNCTION axiom.forbid_identity_change() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id THEN
    RAISE EXCEPTION 'tenant_id and id are immutable on %', TG_TABLE_NAME USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------
-- Installation and tenants
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.installations (
  id uuid PRIMARY KEY,
  deployment_profile text NOT NULL CHECK (deployment_profile IN ('shared', 'dedicated')),
  region text,
  configuration_version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- A dedicated installation hosts exactly one customer tenant; enforced below.

CREATE TABLE axiom.tenants (
  id uuid PRIMARY KEY,
  installation_id uuid NOT NULL REFERENCES axiom.installations(id),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'deleting', 'deleted')),
  residency_policy text,
  schema_version int NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0
);

CREATE FUNCTION axiom.enforce_dedicated_single_tenant() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (SELECT deployment_profile FROM axiom.installations WHERE id = NEW.installation_id) = 'dedicated'
     AND EXISTS (SELECT 1 FROM axiom.tenants t WHERE t.installation_id = NEW.installation_id
                 AND t.id <> NEW.id AND t.status <> 'deleted') THEN
    RAISE EXCEPTION 'dedicated installation already hosts a customer tenant' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER tenants_dedicated_single BEFORE INSERT ON axiom.tenants
  FOR EACH ROW EXECUTE FUNCTION axiom.enforce_dedicated_single_tenant();

CREATE FUNCTION axiom.current_tenant_active() RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT EXISTS (SELECT 1 FROM axiom.tenants WHERE id = axiom.current_tenant() AND status = 'active')
$$;
REVOKE ALL ON FUNCTION axiom.current_tenant_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.current_tenant_active() TO axiom_runtime;

-- ---------------------------------------------------------------------------
-- Global identity (accessible only via narrow authentication functions)
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.principals (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('human', 'workload')),
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE axiom.identity_providers (
  id uuid PRIMARY KEY,
  tenant_id uuid REFERENCES axiom.tenants(id),  -- NULL = installation-scoped provider
  issuer text NOT NULL,
  audience text NOT NULL,
  jwks_uri text,
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (issuer, audience)
);

-- Unique issuer/subject within a trusted provider. No email-based merging.
CREATE TABLE axiom.federated_identities (
  provider_id uuid NOT NULL REFERENCES axiom.identity_providers(id),
  subject text NOT NULL,
  principal_id uuid NOT NULL REFERENCES axiom.principals(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (provider_id, subject)
);

-- Installation-level roles (operator). Grant NO tenant data access.
CREATE TABLE axiom.installation_role_bindings (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES axiom.principals(id),
  role text NOT NULL CHECK (role IN ('installation_operator')),
  valid_until timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- ---------------------------------------------------------------------------
-- Tenant membership, scopes and role bindings
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.memberships (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  principal_id uuid NOT NULL REFERENCES axiom.principals(id),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
  valid_until timestamptz,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, principal_id),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE TABLE axiom.scopes (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('tenant_root', 'project', 'account', 'subscription', 'environment', 'business_unit')),
  parent_id uuid,
  name text NOT NULL,
  resource_reference text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES axiom.scopes(tenant_id, id),
  CHECK (parent_id IS DISTINCT FROM id),
  CHECK ((kind = 'tenant_root') = (parent_id IS NULL))
);
CREATE UNIQUE INDEX scopes_one_root ON axiom.scopes(tenant_id) WHERE kind = 'tenant_root';

CREATE FUNCTION axiom.scopes_no_cycle() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.parent_id IS NOT NULL AND EXISTS (
    WITH RECURSIVE up(id, parent_id, depth) AS (
      SELECT s.id, s.parent_id, 1 FROM axiom.scopes s
       WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.parent_id
      UNION ALL
      SELECT s.id, s.parent_id, up.depth + 1 FROM axiom.scopes s JOIN up ON s.id = up.parent_id
       WHERE s.tenant_id = NEW.tenant_id AND up.depth < 64
    ) SELECT 1 FROM up WHERE up.id = NEW.id) THEN
    RAISE EXCEPTION 'scope hierarchy cycle' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER scopes_no_cycle BEFORE INSERT OR UPDATE ON axiom.scopes
  FOR EACH ROW EXECUTE FUNCTION axiom.scopes_no_cycle();
CREATE TRIGGER scopes_identity BEFORE UPDATE ON axiom.scopes
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_identity_change();

-- Permission catalogue. Built-in and global; tenants cannot invent privileged permissions.
CREATE TABLE axiom.permissions (
  permission text PRIMARY KEY CHECK (permission ~ '^[a-z_]+(\.[a-z_]+)+(:[a-z_]+)?$'),
  privileged boolean NOT NULL,
  description text NOT NULL
);

CREATE TABLE axiom.roles (
  id text PRIMARY KEY CHECK (id ~ '^[a-z_]+$'),
  tenant_id uuid REFERENCES axiom.tenants(id),  -- NULL = built-in role
  description text NOT NULL,
  definition_version int NOT NULL DEFAULT 1
);

CREATE TABLE axiom.role_permissions (
  role_id text NOT NULL REFERENCES axiom.roles(id),
  permission text NOT NULL REFERENCES axiom.permissions(permission),
  PRIMARY KEY (role_id, permission)
);

CREATE FUNCTION axiom.custom_roles_unprivileged() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (SELECT tenant_id FROM axiom.roles WHERE id = NEW.role_id) IS NOT NULL
     AND (SELECT privileged FROM axiom.permissions WHERE permission = NEW.permission) THEN
    RAISE EXCEPTION 'tenant custom roles cannot include privileged permission %', NEW.permission
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER role_permissions_custom_guard BEFORE INSERT OR UPDATE ON axiom.role_permissions
  FOR EACH ROW EXECUTE FUNCTION axiom.custom_roles_unprivileged();

CREATE TABLE axiom.role_bindings (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  principal_id uuid NOT NULL,
  role_id text NOT NULL REFERENCES axiom.roles(id),
  scope_id uuid NOT NULL,
  granted_by uuid,                 -- NULL only for bootstrap by provisioning identity
  reason text NOT NULL,
  valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
  valid_until timestamptz,
  revoked_at timestamptz,
  revoked_by uuid,
  emergency boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  CHECK (granted_by IS NULL OR granted_by <> principal_id),     -- no self-grant
  CHECK (NOT emergency OR valid_until IS NOT NULL)              -- emergency access is time-bound
);
CREATE INDEX role_bindings_principal ON axiom.role_bindings(tenant_id, principal_id);

-- Only revocation fields may change after creation.
CREATE FUNCTION axiom.role_bindings_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.principal_id, NEW.role_id, NEW.scope_id, NEW.granted_by,
      NEW.valid_from, NEW.valid_until, NEW.emergency)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.principal_id, OLD.role_id, OLD.scope_id, OLD.granted_by,
      OLD.valid_from, OLD.valid_until, OLD.emergency) THEN
    RAISE EXCEPTION 'role bindings are immutable except for revocation' USING ERRCODE = '42501';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'revoked role binding cannot be changed' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER role_bindings_guard BEFORE UPDATE ON axiom.role_bindings
  FOR EACH ROW EXECUTE FUNCTION axiom.role_bindings_guard();
CREATE TRIGGER role_bindings_no_delete BEFORE DELETE ON axiom.role_bindings
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Bounds on what a principal may decide (e.g. risk acceptance duration and severity).
CREATE TABLE axiom.delegation_limits (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  principal_id uuid NOT NULL,
  action_class text NOT NULL CHECK (action_class IN ('risk.accept', 'action.approve')),
  scope_id uuid NOT NULL,
  max_priority text NOT NULL CHECK (max_priority IN ('low', 'medium', 'high', 'urgent')),
  max_duration_days int NOT NULL CHECK (max_duration_days BETWEEN 1 AND 730),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Audit (append-only; atomic with the state change it records)
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.audit_events (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_principal_id uuid,
  actor_kind text NOT NULL CHECK (actor_kind IN ('human', 'workload', 'system')),
  on_behalf_of uuid,
  correlation_id text NOT NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  outcome text NOT NULL CHECK (outcome IN ('committed', 'denied', 'failed')),
  reason_code text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  schema_version int NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id),
  CHECK (actor_kind = 'system' OR actor_principal_id IS NOT NULL)
);
CREATE INDEX audit_events_time ON axiom.audit_events(tenant_id, occurred_at);
CREATE INDEX audit_events_resource ON axiom.audit_events(tenant_id, resource_type, resource_id);
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON axiom.audit_events
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Transactional outbox and consumer inbox (at-least-once delivery)
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.outbox (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  topic text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  attempts int NOT NULL DEFAULT 0,
  lease_owner text,
  lease_expires_at timestamptz,
  delivered_at timestamptz,
  last_error text,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX outbox_ready ON axiom.outbox(available_at) WHERE delivered_at IS NULL;

CREATE FUNCTION axiom.outbox_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.topic, NEW.aggregate_type, NEW.aggregate_id, NEW.payload, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.topic, OLD.aggregate_type, OLD.aggregate_id, OLD.payload, OLD.created_at) THEN
    RAISE EXCEPTION 'outbox message content is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.delivered_at IS NOT NULL THEN
    RAISE EXCEPTION 'delivered outbox message is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER outbox_guard BEFORE UPDATE ON axiom.outbox
  FOR EACH ROW EXECUTE FUNCTION axiom.outbox_guard();
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON axiom.outbox
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.inbox (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  consumer text NOT NULL,
  message_id uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, consumer, message_id)
);

-- ---------------------------------------------------------------------------
-- Evidence objects (bytes live in object storage; this is the trusted metadata)
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.evidence_objects (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  scope_id uuid NOT NULL,
  object_key text NOT NULL,
  hash_algorithm text NOT NULL DEFAULT 'sha256' CHECK (hash_algorithm = 'sha256'),
  expected_digest text NOT NULL CHECK (expected_digest ~ '^[0-9a-f]{64}$'),
  expected_size bigint NOT NULL CHECK (expected_size >= 0),
  observed_digest text CHECK (observed_digest ~ '^[0-9a-f]{64}$'),
  observed_size bigint CHECK (observed_size >= 0),
  media_type text NOT NULL CHECK (length(media_type) BETWEEN 3 AND 255),
  original_filename text,
  classification text NOT NULL CHECK (classification IN ('internal', 'confidential', 'restricted')),
  retention_policy text NOT NULL DEFAULT 'tenant_default',
  status text NOT NULL CHECK (status IN ('pending', 'uploaded', 'verified', 'rejected', 'deleting', 'deleted')),
  rejection_reason text,
  storage_version text,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  uploaded_at timestamptz,
  verified_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, object_key),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  -- Object keys are server-generated under the tenant namespace.
  CHECK (object_key = 'tenants/' || tenant_id::text || '/evidence/' || id::text),
  CHECK (status <> 'verified' OR (observed_digest = expected_digest AND observed_size = expected_size
                                   AND verified_at IS NOT NULL)),
  CHECK (status <> 'rejected' OR rejection_reason IS NOT NULL)
);

CREATE FUNCTION axiom.evidence_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'pending' OR NEW.observed_digest IS NOT NULL OR NEW.observed_size IS NOT NULL
       OR NEW.record_version <> 0 THEN
      RAISE EXCEPTION 'evidence must be created as pending' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.scope_id, NEW.object_key, NEW.expected_digest, NEW.expected_size,
      NEW.classification, NEW.created_by, NEW.created_at, NEW.media_type)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.scope_id, OLD.object_key, OLD.expected_digest, OLD.expected_size,
      OLD.classification, OLD.created_by, OLD.created_at, OLD.media_type) THEN
    RAISE EXCEPTION 'evidence identity and declared properties are immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'evidence record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  IF NOT ((OLD.status, NEW.status) IN (('pending', 'uploaded'), ('uploaded', 'verified'),
          ('pending', 'rejected'), ('uploaded', 'rejected'),
          ('verified', 'deleting'), ('rejected', 'deleting'), ('deleting', 'deleted'))) THEN
    RAISE EXCEPTION 'evidence status % -> % not permitted', OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'verified' AND (NEW.observed_digest, NEW.observed_size)
       IS DISTINCT FROM (OLD.observed_digest, OLD.observed_size) THEN
    RAISE EXCEPTION 'verified evidence digest is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER evidence_guard BEFORE INSERT OR UPDATE ON axiom.evidence_objects
  FOR EACH ROW EXECUTE FUNCTION axiom.evidence_guard();
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON axiom.evidence_objects
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
ALTER TABLE axiom.installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.installations FORCE ROW LEVEL SECURITY;
CREATE POLICY installations_read ON axiom.installations FOR SELECT TO axiom_runtime, axiom_authn USING (true);

ALTER TABLE axiom.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_runtime_read ON axiom.tenants FOR SELECT TO axiom_runtime
  USING (id = axiom.current_tenant());
CREATE POLICY tenants_authn_read ON axiom.tenants FOR SELECT TO axiom_authn USING (true);

ALTER TABLE axiom.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.principals FORCE ROW LEVEL SECURITY;
CREATE POLICY principals_authn_read ON axiom.principals FOR SELECT TO axiom_authn USING (true);
-- Runtime sees only principals that are members of the current tenant.
CREATE POLICY principals_runtime_read ON axiom.principals FOR SELECT TO axiom_runtime
  USING (EXISTS (SELECT 1 FROM axiom.memberships m
                 WHERE m.tenant_id = axiom.current_tenant() AND m.principal_id = principals.id));

ALTER TABLE axiom.identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY idp_authn_read ON axiom.identity_providers FOR SELECT TO axiom_authn USING (true);

ALTER TABLE axiom.federated_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.federated_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY fed_authn_read ON axiom.federated_identities FOR SELECT TO axiom_authn USING (true);

ALTER TABLE axiom.installation_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.installation_role_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY irb_authn_read ON axiom.installation_role_bindings FOR SELECT TO axiom_authn USING (true);

ALTER TABLE axiom.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_authn_read ON axiom.memberships FOR SELECT TO axiom_authn USING (true);

ALTER TABLE axiom.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.roles FORCE ROW LEVEL SECURITY;
CREATE POLICY roles_read ON axiom.roles FOR SELECT TO axiom_runtime, axiom_authn
  USING (tenant_id IS NULL OR tenant_id = axiom.current_tenant());
-- Migrations (as axiom_owner) maintain the built-in catalogue only.
CREATE POLICY roles_builtin_catalogue ON axiom.roles TO axiom_owner
  USING (tenant_id IS NULL) WITH CHECK (tenant_id IS NULL);

-- permissions and role_permissions are a global, non-secret catalogue.
GRANT SELECT ON axiom.permissions, axiom.role_permissions TO axiom_runtime, axiom_authn;
GRANT SELECT ON axiom.installations, axiom.tenants, axiom.principals, axiom.roles TO axiom_runtime;
GRANT SELECT ON axiom.installations, axiom.tenants, axiom.principals, axiom.identity_providers,
  axiom.federated_identities, axiom.installation_role_bindings, axiom.memberships, axiom.roles TO axiom_authn;

-- Standard tenant boundary policy applied to tenant-owned tables.
CREATE FUNCTION axiom.apply_tenant_policy(p_table text) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  EXECUTE format('ALTER TABLE axiom.%I ENABLE ROW LEVEL SECURITY', p_table);
  EXECUTE format('ALTER TABLE axiom.%I FORCE ROW LEVEL SECURITY', p_table);
  EXECUTE format(
    'CREATE POLICY tenant_boundary ON axiom.%I TO axiom_runtime
       USING (tenant_id = axiom.current_tenant() AND axiom.current_tenant_active())
       WITH CHECK (tenant_id = axiom.current_tenant() AND axiom.current_tenant_active())', p_table);
END
$$;
REVOKE ALL ON FUNCTION axiom.apply_tenant_policy(text) FROM PUBLIC;

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY[
  'memberships', 'scopes', 'role_bindings', 'delegation_limits', 'audit_events',
  'outbox', 'inbox', 'evidence_objects']) AS t;

GRANT SELECT ON axiom.memberships, axiom.scopes, axiom.role_bindings, axiom.delegation_limits TO axiom_runtime;
GRANT INSERT ON axiom.memberships, axiom.scopes, axiom.role_bindings, axiom.delegation_limits TO axiom_runtime;
GRANT UPDATE (status, valid_until, record_version) ON axiom.memberships TO axiom_runtime;
GRANT UPDATE (revoked_at, revoked_by) ON axiom.role_bindings TO axiom_runtime;
GRANT UPDATE (revoked_at) ON axiom.delegation_limits TO axiom_runtime;
GRANT SELECT, INSERT ON axiom.audit_events TO axiom_runtime;
GRANT SELECT, INSERT ON axiom.outbox, axiom.inbox TO axiom_runtime;
GRANT SELECT, INSERT ON axiom.evidence_objects TO axiom_runtime;
GRANT UPDATE (status, observed_digest, observed_size, rejection_reason, storage_version,
  uploaded_at, verified_at, record_version) ON axiom.evidence_objects TO axiom_runtime;

-- Outbox relay: cross-tenant read and delivery bookkeeping on the outbox only.
CREATE POLICY outbox_relay ON axiom.outbox FOR SELECT TO axiom_relay USING (true);
CREATE POLICY outbox_relay_update ON axiom.outbox FOR UPDATE TO axiom_relay USING (true) WITH CHECK (true);
GRANT SELECT ON axiom.outbox TO axiom_relay;
GRANT UPDATE (attempts, lease_owner, lease_expires_at, delivered_at, last_error, available_at)
  ON axiom.outbox TO axiom_relay;

-- ---------------------------------------------------------------------------
-- Installation-level security events (denials without a tenant attribution,
-- e.g. selecting a tenant without membership). Contains no tenant payload.
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.security_events (
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  principal_id uuid,
  requested_tenant text,
  correlation_id text NOT NULL,
  event_type text NOT NULL,
  reason_code text NOT NULL
);
CREATE TRIGGER security_events_append_only BEFORE UPDATE OR DELETE ON axiom.security_events
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();
ALTER TABLE axiom.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY security_events_write ON axiom.security_events FOR INSERT TO axiom_runtime WITH CHECK (true);
GRANT INSERT ON axiom.security_events TO axiom_runtime;   -- write-only for the application

-- ---------------------------------------------------------------------------
-- Provisioning identity (installation tooling). Creates tenants and bootstrap
-- memberships; has no access to evidence, cases or audit history.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA axiom TO axiom_provisioner;
GRANT EXECUTE ON FUNCTION axiom.current_tenant(), axiom.current_principal(), axiom.context_part(int),
  axiom.tx_marker() TO axiom_provisioner;
CREATE POLICY prov_installations ON axiom.installations TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_tenants ON axiom.tenants TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_principals ON axiom.principals TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_idp ON axiom.identity_providers TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_fed ON axiom.federated_identities TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_irb ON axiom.installation_role_bindings TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_memberships ON axiom.memberships TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_scopes ON axiom.scopes TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_role_bindings ON axiom.role_bindings TO axiom_provisioner USING (true) WITH CHECK (true);
CREATE POLICY prov_audit_insert ON axiom.audit_events FOR INSERT TO axiom_provisioner WITH CHECK (true);
GRANT SELECT, INSERT ON axiom.installations, axiom.tenants, axiom.principals, axiom.identity_providers,
  axiom.federated_identities, axiom.installation_role_bindings, axiom.memberships, axiom.scopes,
  axiom.role_bindings TO axiom_provisioner;
GRANT UPDATE (status, display_name, record_version) ON axiom.tenants TO axiom_provisioner;
GRANT UPDATE (status) ON axiom.principals, axiom.identity_providers TO axiom_provisioner;
GRANT UPDATE (revoked_at) ON axiom.installation_role_bindings TO axiom_provisioner;
GRANT INSERT ON axiom.audit_events TO axiom_provisioner;
GRANT SELECT ON axiom.roles, axiom.permissions, axiom.role_permissions TO axiom_provisioner;
CREATE POLICY prov_roles ON axiom.roles FOR SELECT TO axiom_provisioner USING (true);

-- ---------------------------------------------------------------------------
-- Narrow authentication lookups (SECURITY DEFINER) in schema axiom_auth, owned by
-- axiom_authn. axiom_authn can read identity/membership rows; axiom_runtime can only
-- EXECUTE these functions and never SELECT those rows directly.
-- ---------------------------------------------------------------------------
CREATE SCHEMA axiom_auth AUTHORIZATION axiom_authn;

SET LOCAL ROLE axiom_authn;
REVOKE ALL ON SCHEMA axiom_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA axiom_auth TO axiom_runtime;

-- Resolve an active principal from a validated (issuer, audience, subject).
CREATE FUNCTION axiom_auth.resolve_principal(p_issuer text, p_audience text, p_subject text)
RETURNS TABLE (principal_id uuid, principal_kind text, provider_tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.id, p.kind, idp.tenant_id
    FROM axiom.identity_providers idp
    JOIN axiom.federated_identities f ON f.provider_id = idp.id
    JOIN axiom.principals p ON p.id = f.principal_id
   WHERE idp.issuer = p_issuer AND idp.audience = p_audience AND idp.status = 'active'
     AND f.subject = p_subject AND p.status = 'active'
$$;

-- Active membership of a principal in a tenant, only when the tenant is active.
CREATE FUNCTION axiom_auth.membership(p_principal uuid, p_tenant uuid)
RETURNS TABLE (membership_id uuid, tenant_status text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT m.id, t.status
    FROM axiom.memberships m JOIN axiom.tenants t ON t.id = m.tenant_id
   WHERE m.principal_id = p_principal AND m.tenant_id = p_tenant
     AND m.status = 'active' AND m.valid_from <= clock_timestamp()
     AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp())
     AND t.status = 'active'
$$;

-- Resolve a tenant selector (slug or id) without revealing tenants the principal cannot use.
CREATE FUNCTION axiom_auth.select_tenant(p_principal uuid, p_selector text)
RETURNS TABLE (tenant_id uuid, membership_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.id, m.id
    FROM axiom.tenants t JOIN axiom.memberships m ON m.tenant_id = t.id
   WHERE (t.slug = p_selector OR t.id::text = p_selector)
     AND m.principal_id = p_principal AND m.status = 'active' AND t.status = 'active'
     AND m.valid_from <= clock_timestamp()
     AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp())
$$;

-- Tenants a principal may select (for a tenant picker); returns no evidence.
CREATE FUNCTION axiom_auth.list_tenants(p_principal uuid)
RETURNS TABLE (tenant_id uuid, slug text, display_name text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.id, t.slug, t.display_name
    FROM axiom.memberships m JOIN axiom.tenants t ON t.id = m.tenant_id
   WHERE m.principal_id = p_principal AND m.status = 'active' AND t.status = 'active'
     AND m.valid_from <= clock_timestamp()
     AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp())
   ORDER BY t.slug
$$;

CREATE FUNCTION axiom_auth.installation_roles(p_principal uuid)
RETURNS TABLE (role text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT b.role FROM axiom.installation_role_bindings b
   WHERE b.principal_id = p_principal AND b.revoked_at IS NULL
     AND (b.valid_until IS NULL OR b.valid_until > clock_timestamp())
$$;

-- Active tenant identifiers only, for scheduled per-tenant sweeps (e.g. risk
-- acceptance expiry). Returns no tenant data; each sweep then binds one tenant.
CREATE FUNCTION axiom_auth.active_tenant_ids()
RETURNS TABLE (tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$ SELECT t.id FROM axiom.tenants t WHERE t.status = 'active' ORDER BY t.id $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA axiom_auth FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA axiom_auth TO axiom_runtime;

SET LOCAL ROLE axiom_owner;

-- ---------------------------------------------------------------------------
-- Built-in permission and role catalogue (docs/REQUIREMENTS.md AUTHZ-*)
-- ---------------------------------------------------------------------------
INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('case.read', false, 'Read case summaries in scope'),
 ('case.create', false, 'Create cases'),
 ('case.assign', false, 'Assign case owner'),
 ('asset.read', false, 'Read assets in scope'),
 ('asset.manage', false, 'Record asset lifecycle and versions with evidence'),
 ('report.read', false, 'Read reports in scope'),
 ('investigation.request', false, 'Start an investigation'),
 ('assessment.record', false, 'Record an assessment with limitations'),
 ('remediation.propose', false, 'Plan remediation'),
 ('remediation.update', false, 'Report remediation change evidence'),
 ('verification.request', false, 'Request verification'),
 ('verification.record', false, 'Record a verification outcome'),
 ('closure.propose', false, 'Close verified or duplicate cases'),
 ('override.propose', false, 'Propose a priority override'),
 ('case.reopen', false, 'Reopen a closed case with a recorded reason'),
 ('evidence.upload', false, 'Upload evidence'),
 ('evidence.read:internal', false, 'Read internal evidence content'),
 ('evidence.read:confidential', false, 'Read confidential evidence content'),
 ('evidence.read:restricted', true, 'Read restricted evidence content'),
 ('proposal.read', false, 'Read action proposals'),
 ('action.approve', true, 'Approve action classes within delegation'),
 ('case.dismiss', true, 'Dismiss a case as not supported'),
 ('risk.accept', true, 'Accept risk within delegated limits'),
 ('policy.draft', false, 'Draft policies'),
 ('policy.simulate', false, 'Simulate policy impact'),
 ('policy.publish', true, 'Publish policies'),
 ('connection.configure', true, 'Configure integrations'),
 ('audit.read', true, 'Read audit history'),
 ('membership.manage', true, 'Manage tenant memberships'),
 ('role.assign', true, 'Assign roles within delegation rules'),
 ('scope.manage', false, 'Manage scopes');

INSERT INTO axiom.roles(id, description) VALUES
 ('viewer', 'Read authorised cases, assets and reports'),
 ('analyst', 'Investigate, assess, propose remediation and closure'),
 ('remediation_owner', 'Update assigned remediation and supply change evidence'),
 ('approver', 'Approve delegated action classes and supported dismissals'),
 ('risk_owner', 'Accept risk within delegated limits'),
 ('policy_admin', 'Draft, simulate and publish policies; configure integrations'),
 ('auditor', 'Read audit history and reports without mutation'),
 ('evidence_reader', 'Explicit grant to read internal and confidential evidence'),
 ('evidence_reader_restricted', 'Explicit grant to read restricted evidence'),
 ('tenant_admin', 'Manage memberships and role assignments; no evidence or risk authority');

INSERT INTO axiom.role_permissions(role_id, permission)
SELECT r, p FROM (VALUES
 ('viewer', 'case.read'), ('viewer', 'asset.read'), ('viewer', 'report.read'),
 ('analyst', 'case.read'), ('analyst', 'asset.read'), ('analyst', 'report.read'),
 ('analyst', 'case.create'), ('analyst', 'case.assign'), ('analyst', 'investigation.request'),
 ('analyst', 'assessment.record'), ('analyst', 'remediation.propose'), ('analyst', 'verification.record'),
 ('analyst', 'closure.propose'), ('analyst', 'override.propose'), ('analyst', 'case.reopen'),
 ('analyst', 'asset.manage'), ('analyst', 'evidence.upload'),('analyst', 'evidence.read:internal'), ('analyst', 'evidence.read:confidential'),
 ('remediation_owner', 'case.read'), ('remediation_owner', 'remediation.update'),
 ('remediation_owner', 'verification.request'), ('remediation_owner', 'evidence.upload'),
 ('remediation_owner', 'evidence.read:internal'),
 ('approver', 'case.read'), ('approver', 'proposal.read'), ('approver', 'action.approve'), ('approver', 'case.dismiss'),
 ('risk_owner', 'case.read'), ('risk_owner', 'risk.accept'), ('risk_owner', 'evidence.read:internal'),
 ('policy_admin', 'policy.draft'), ('policy_admin', 'policy.simulate'), ('policy_admin', 'policy.publish'),
 ('policy_admin', 'connection.configure'),
 ('auditor', 'audit.read'), ('auditor', 'report.read'), ('auditor', 'case.read'),
 ('evidence_reader', 'evidence.read:internal'), ('evidence_reader', 'evidence.read:confidential'),
 ('evidence_reader_restricted', 'evidence.read:restricted'),
 ('tenant_admin', 'membership.manage'), ('tenant_admin', 'role.assign'), ('tenant_admin', 'scope.manage')
) AS v(r, p);
