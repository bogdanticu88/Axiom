-- 0003 Ingestion and inventory (Phase B): connections, runs, pages, source records,
-- observations, quarantine, asset identifiers, identity candidates, occurrence history,
-- business context versions.
--
-- Principles (S 5, D 3-5):
--   * Original files and API pages are preserved as verified evidence objects; every
--     observation points back to its raw evidence and a locator inside it.
--   * Pages commit atomically with everything derived from them, and only while the
--     committing worker still holds the run lease (fencing). Checkpoints therefore only
--     advance after durable writes.
--   * Strong identifiers (provider IDs, digests, source-scoped IDs) are unique per tenant;
--     weak identifiers (hostnames, IPs, names) are never unique and never merge assets.
--   * Absence from a scan is an observation, never a closure.

-- ---------------------------------------------------------------------------
-- Connections and checkpoints
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.connections (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  scope_id uuid NOT NULL,
  adapter text NOT NULL CHECK (adapter ~ '^[a-z0-9_]+$'),
  adapter_kind text NOT NULL CHECK (adapter_kind IN ('scanner', 'context', 'intelligence', 'workflow', 'evidence')),
  display_name text NOT NULL,
  base_url text,
  -- Reference to a secret held outside the database (never the secret itself).
  credential_ref text CHECK (credential_ref IS NULL OR credential_ref ~ '^secretref:[A-Za-z0-9._/-]+$'),
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id)
);

CREATE TABLE axiom.connection_checkpoints (
  tenant_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  stream text NOT NULL,
  cursor jsonb NOT NULL,
  last_durable_run_id uuid NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, connection_id, stream),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Ingestion runs and pages
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.ingestion_runs (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  scope_id uuid NOT NULL,
  connection_id uuid,
  source_kind text NOT NULL CHECK (source_kind IN ('file_import', 'api_sync')),
  adapter text NOT NULL,
  adapter_version text NOT NULL,
  raw_evidence_id uuid,                       -- original file for imports
  declared_subject jsonb,                     -- importer assertion when the format lacks a subject
  declared_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  coverage text NOT NULL DEFAULT 'unknown' CHECK (coverage IN ('complete', 'partial', 'failed', 'unknown')),
  coverage_reason text,
  requested_by uuid NOT NULL,
  lease_owner text,
  lease_token bigint NOT NULL DEFAULT 0,      -- fencing token, incremented on every claim
  lease_expires_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  counts jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_summary text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  started_at timestamptz,
  finished_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id),
  FOREIGN KEY (tenant_id, raw_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  CHECK ((source_kind = 'file_import') = (raw_evidence_id IS NOT NULL)),
  CHECK (status IN ('queued', 'running') OR finished_at IS NOT NULL),
  -- A run that did not complete cannot claim complete coverage.
  CHECK (coverage <> 'complete' OR status = 'completed')
);
CREATE INDEX ingestion_runs_ready ON axiom.ingestion_runs(tenant_id, status, lease_expires_at);

CREATE FUNCTION axiom.ingestion_runs_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'queued' OR NEW.coverage <> 'unknown' OR NEW.lease_token <> 0 THEN
      RAISE EXCEPTION 'ingestion runs are created queued with unknown coverage' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.scope_id, NEW.connection_id, NEW.source_kind, NEW.adapter, NEW.raw_evidence_id,
      NEW.declared_subject, NEW.declared_scope, NEW.requested_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.scope_id, OLD.connection_id, OLD.source_kind, OLD.adapter, OLD.raw_evidence_id,
      OLD.declared_subject, OLD.declared_scope, OLD.requested_by, OLD.created_at) THEN
    RAISE EXCEPTION 'ingestion run definition is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('completed', 'failed', 'cancelled') THEN
    RAISE EXCEPTION 'finished ingestion run is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.lease_token < OLD.lease_token THEN
    RAISE EXCEPTION 'lease token cannot decrease' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'ingestion run record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER ingestion_runs_guard BEFORE INSERT OR UPDATE ON axiom.ingestion_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.ingestion_runs_guard();
CREATE TRIGGER ingestion_runs_no_delete BEFORE DELETE ON axiom.ingestion_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.ingestion_pages (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  page_key text NOT NULL,
  page_digest text NOT NULL CHECK (page_digest ~ '^[0-9a-f]{64}$'),
  evidence_id uuid,                            -- raw API page, when the page is not part of an imported file
  record_count int NOT NULL CHECK (record_count >= 0),
  lease_token bigint NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, run_id, page_key),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.ingestion_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id)
);
CREATE TRIGGER ingestion_pages_append_only BEFORE UPDATE OR DELETE ON axiom.ingestion_pages
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Fencing: a page commits only while the run is running and the committing lease is current.
CREATE FUNCTION axiom.ingestion_page_fence() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM axiom.ingestion_runs r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.run_id
                   AND r.status = 'running' AND r.lease_token = NEW.lease_token
                   AND r.lease_expires_at > clock_timestamp()) THEN
    RAISE EXCEPTION 'stale or expired ingestion lease' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER ingestion_page_fence BEFORE INSERT ON axiom.ingestion_pages
  FOR EACH ROW EXECUTE FUNCTION axiom.ingestion_page_fence();

-- ---------------------------------------------------------------------------
-- Source records, observations and quarantine
-- ---------------------------------------------------------------------------
-- Stable source identity with version history: one row per (namespace, external id, source version).
CREATE TABLE axiom.source_records (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  source_namespace text NOT NULL,
  record_type text NOT NULL CHECK (record_type IN ('finding', 'asset')),
  external_id text NOT NULL,
  version_key text NOT NULL,
  first_run_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, source_namespace, record_type, external_id, version_key),
  FOREIGN KEY (tenant_id, first_run_id) REFERENCES axiom.ingestion_runs(tenant_id, id)
);
CREATE TRIGGER source_records_append_only BEFORE UPDATE OR DELETE ON axiom.source_records
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.observations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid NOT NULL,
  source_record_id uuid NOT NULL,
  raw_evidence_id uuid NOT NULL,
  raw_locator text NOT NULL,                  -- JSON pointer or chunk/offset within the raw evidence
  observation_type text NOT NULL CHECK (observation_type IN
     ('finding_reported', 'finding_fixed_by_source', 'finding_suppressed_by_source', 'asset_context', 'tombstone')),
  subject_asset_id uuid,
  subject_asset_version_id uuid,
  source_time timestamptz,
  collected_at timestamptz NOT NULL,
  expires_at timestamptz,
  normalised jsonb NOT NULL,
  source_fields jsonb NOT NULL,
  observation_digest text NOT NULL CHECK (observation_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, run_id, source_record_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.ingestion_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, source_record_id) REFERENCES axiom.source_records(tenant_id, id),
  FOREIGN KEY (tenant_id, raw_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  FOREIGN KEY (tenant_id, subject_asset_id) REFERENCES axiom.assets(tenant_id, id),
  FOREIGN KEY (tenant_id, subject_asset_version_id) REFERENCES axiom.asset_versions(tenant_id, id)
);
CREATE INDEX observations_subject ON axiom.observations(tenant_id, subject_asset_id, collected_at);
CREATE TRIGGER observations_append_only BEFORE UPDATE OR DELETE ON axiom.observations
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.observation_relations (
  tenant_id uuid NOT NULL,
  from_observation_id uuid NOT NULL,
  to_observation_id uuid NOT NULL,
  relation text NOT NULL CHECK (relation IN ('supersedes', 'contradicts', 'corroborates')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, from_observation_id, to_observation_id, relation),
  FOREIGN KEY (tenant_id, from_observation_id) REFERENCES axiom.observations(tenant_id, id),
  FOREIGN KEY (tenant_id, to_observation_id) REFERENCES axiom.observations(tenant_id, id),
  CHECK (from_observation_id <> to_observation_id)
);
CREATE TRIGGER observation_relations_append_only BEFORE UPDATE OR DELETE ON axiom.observation_relations
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.quarantined_records (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid NOT NULL,
  raw_evidence_id uuid NOT NULL,
  raw_locator text NOT NULL,
  reason_code text NOT NULL CHECK (reason_code ~ '^[a-z_]+$'),
  detail text NOT NULL,
  record_digest text CHECK (record_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, run_id, raw_locator, reason_code),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.ingestion_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, raw_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id)
);
CREATE TRIGGER quarantined_records_append_only BEFORE UPDATE OR DELETE ON axiom.quarantined_records
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Asset identity
-- ---------------------------------------------------------------------------
ALTER TABLE axiom.assets ADD COLUMN identity_status text NOT NULL DEFAULT 'resolved'
  CHECK (identity_status IN ('resolved', 'provisional', 'conflict'));

CREATE TABLE axiom.asset_identifiers (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  asset_id uuid NOT NULL,
  namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9_]+$'),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
  strength text NOT NULL CHECK (strength IN ('strong', 'weak')),
  origin text NOT NULL CHECK (origin IN ('observed', 'declared_by_importer', 'reviewer')),
  source_observation_id uuid,
  valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
  valid_until timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES axiom.assets(tenant_id, id),
  FOREIGN KEY (tenant_id, source_observation_id) REFERENCES axiom.observations(tenant_id, id)
);
-- Strong identifiers identify at most one asset per tenant; weak identifiers are never unique.
CREATE UNIQUE INDEX asset_identifiers_strong_unique ON axiom.asset_identifiers(tenant_id, namespace, value)
  WHERE strength = 'strong' AND valid_until IS NULL;
CREATE UNIQUE INDEX asset_identifiers_asset_ns_value ON axiom.asset_identifiers(tenant_id, asset_id, namespace, value)
  WHERE valid_until IS NULL;
CREATE INDEX asset_identifiers_lookup ON axiom.asset_identifiers(tenant_id, namespace, value);

CREATE TABLE axiom.identity_candidates (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid,
  observation_id uuid,
  method text NOT NULL CHECK (method IN ('weak_identifier_overlap', 'strong_identifier_conflict')),
  asset_ids uuid[] NOT NULL CHECK (cardinality(asset_ids) >= 2),
  matched_identifiers jsonb NOT NULL,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'confirmed_same', 'confirmed_distinct', 'dismissed')),
  resolved_by uuid,
  resolved_at timestamptz,
  resolution_rationale text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.ingestion_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, observation_id) REFERENCES axiom.observations(tenant_id, id),
  CHECK ((status = 'open') = (resolved_at IS NULL))
);
CREATE INDEX identity_candidates_open ON axiom.identity_candidates(tenant_id, status);

-- ---------------------------------------------------------------------------
-- Occurrence history and business context
-- ---------------------------------------------------------------------------
ALTER TABLE axiom.finding_occurrences ADD COLUMN title text;
ALTER TABLE axiom.finding_occurrences ADD COLUMN source_severity text;
ALTER TABLE axiom.finding_occurrences ADD COLUMN first_run_id uuid;
ALTER TABLE axiom.finding_occurrences ADD CONSTRAINT finding_occurrences_first_run
  FOREIGN KEY (tenant_id, first_run_id) REFERENCES axiom.ingestion_runs(tenant_id, id);

CREATE TABLE axiom.occurrence_observations (
  tenant_id uuid NOT NULL,
  occurrence_id uuid NOT NULL,
  run_id uuid NOT NULL,
  observation_id uuid,
  observed_status text NOT NULL CHECK (observed_status IN
     ('present', 'fixed_by_source', 'suppressed_by_source', 'absent_in_complete_scan')),
  source_time timestamptz,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, occurrence_id, run_id),
  FOREIGN KEY (tenant_id, occurrence_id) REFERENCES axiom.finding_occurrences(tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.ingestion_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, observation_id) REFERENCES axiom.observations(tenant_id, id),
  CHECK ((observed_status = 'absent_in_complete_scan') = (observation_id IS NULL))
);
CREATE TRIGGER occurrence_observations_append_only BEFORE UPDATE OR DELETE ON axiom.occurrence_observations
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Owner, criticality, environment: asserted (by tags or people) or observed, with effective dates.
CREATE TABLE axiom.business_context_versions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  asset_id uuid NOT NULL,
  owner_ref text,
  criticality text CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  environment text,
  data_classification text,
  basis text NOT NULL CHECK (basis IN ('source_tag_assertion', 'user_assertion', 'observed')),
  source_observation_id uuid,
  asserted_by uuid,
  effective_from timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES axiom.assets(tenant_id, id),
  FOREIGN KEY (tenant_id, source_observation_id) REFERENCES axiom.observations(tenant_id, id),
  CHECK (basis <> 'source_tag_assertion' OR source_observation_id IS NOT NULL),
  CHECK (basis <> 'user_assertion' OR asserted_by IS NOT NULL)
);
CREATE INDEX business_context_current ON axiom.business_context_versions(tenant_id, asset_id, effective_from DESC);
CREATE TRIGGER business_context_append_only BEFORE UPDATE OR DELETE ON axiom.business_context_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Permissions and the ingestion worker role
-- ---------------------------------------------------------------------------
INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('ingestion.import', false, 'Import scanner reports and request synchronisation'),
 ('ingestion.read', false, 'Read ingestion runs, coverage and quarantine'),
 ('identity.review', false, 'Resolve asset identity candidates');
INSERT INTO axiom.roles(id, description) VALUES
 ('ingestion_worker', 'Workload role for the tenant system principal that executes ingestion runs');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'ingestion.import'), ('analyst', 'ingestion.read'), ('analyst', 'identity.review'),
 ('viewer', 'ingestion.read'), ('auditor', 'ingestion.read'), ('policy_admin', 'ingestion.read'),
 ('ingestion_worker', 'case.read'), ('ingestion_worker', 'case.create'), ('ingestion_worker', 'case.reopen'),
 ('ingestion_worker', 'asset.read'), ('ingestion_worker', 'asset.manage'), ('ingestion_worker', 'ingestion.read'),
 ('ingestion_worker', 'evidence.upload');

-- ---------------------------------------------------------------------------
-- RLS and grants
-- ---------------------------------------------------------------------------
SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY[
  'connections', 'connection_checkpoints', 'ingestion_runs', 'ingestion_pages', 'source_records', 'observations',
  'observation_relations', 'quarantined_records', 'asset_identifiers', 'identity_candidates',
  'occurrence_observations', 'business_context_versions']) AS t;

GRANT SELECT, INSERT ON axiom.connections, axiom.connection_checkpoints, axiom.ingestion_runs, axiom.ingestion_pages,
  axiom.source_records, axiom.observations, axiom.observation_relations, axiom.quarantined_records, axiom.asset_identifiers,
  axiom.identity_candidates, axiom.occurrence_observations, axiom.business_context_versions TO axiom_runtime;
GRANT UPDATE (status, display_name, base_url, credential_ref, config, record_version) ON axiom.connections TO axiom_runtime;
GRANT UPDATE (cursor, last_durable_run_id, updated_at, record_version) ON axiom.connection_checkpoints TO axiom_runtime;
GRANT UPDATE (status, coverage, coverage_reason, lease_owner, lease_token, lease_expires_at, attempts, counts,
  error_summary, started_at, finished_at, adapter_version, record_version) ON axiom.ingestion_runs TO axiom_runtime;
GRANT UPDATE (valid_until) ON axiom.asset_identifiers TO axiom_runtime;
GRANT UPDATE (status, resolved_by, resolved_at, resolution_rationale, record_version) ON axiom.identity_candidates TO axiom_runtime;
GRANT UPDATE (identity_status) ON axiom.assets TO axiom_runtime;

-- ---------------------------------------------------------------------------
-- Tenant system principal (executes ingestion and scheduled sweeps)
-- ---------------------------------------------------------------------------
ALTER TABLE axiom.tenants ADD COLUMN system_principal_id uuid REFERENCES axiom.principals(id);
GRANT UPDATE (system_principal_id) ON axiom.tenants TO axiom_provisioner;

SET LOCAL ROLE axiom_authn;
-- Active tenants with their system principal, for workers that bind one tenant at a time.
CREATE FUNCTION axiom_auth.active_tenant_workers()
RETURNS TABLE (tenant_id uuid, system_principal_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.id, t.system_principal_id FROM axiom.tenants t
   WHERE t.status = 'active' AND t.system_principal_id IS NOT NULL ORDER BY t.id
$$;
REVOKE ALL ON FUNCTION axiom_auth.active_tenant_workers() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom_auth.active_tenant_workers() TO axiom_runtime;
SET LOCAL ROLE axiom_owner;
