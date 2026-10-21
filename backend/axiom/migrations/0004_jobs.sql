-- 0004 Durable jobs (ADR 0006): PostgreSQL-backed runner with leases, fencing, step deadlines,
-- claim counting, versioned handlers, effect intents and restore detection.
--
-- Safety properties (enforced here, not only in Python):
--   * every job write by a worker is fenced on lease_token;
--   * a job claimed more than max_claims times is dead-lettered (poison jobs cannot loop forever);
--   * effect intents are unique per operation key and record the database fingerprint
--     (cluster system identifier, timeline, database OID) under which they were written, so a
--     restored database is detectable without an operator remembering a runbook step;
--   * terminal job and intent states are immutable.

CREATE FUNCTION axiom.db_fingerprint() RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT (SELECT system_identifier::text FROM pg_control_system()) || ':' ||
         (SELECT timeline_id::text FROM pg_control_checkpoint()) || ':' ||
         (SELECT oid::text FROM pg_database WHERE datname = current_database())
$$;
REVOKE ALL ON FUNCTION axiom.db_fingerprint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.db_fingerprint() TO axiom_runtime, axiom_provisioner;

-- Installation-level acknowledgement that effects may run under a given database fingerprint.
-- The fingerprint at install time is acknowledged automatically; after a restore (new cluster,
-- new timeline or new database) effects on integrations without reliable lookup stay blocked
-- until an operator reconciles pending effects and acknowledges the new fingerprint.
CREATE TABLE axiom.recovery_acknowledgements (
  fingerprint text PRIMARY KEY,
  acknowledged_by text NOT NULL,
  note text NOT NULL,
  acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER recovery_acknowledgements_append_only BEFORE UPDATE OR DELETE ON axiom.recovery_acknowledgements
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();
GRANT SELECT ON axiom.recovery_acknowledgements TO axiom_runtime;
GRANT SELECT, INSERT ON axiom.recovery_acknowledgements TO axiom_provisioner;
INSERT INTO axiom.recovery_acknowledgements(fingerprint, acknowledged_by, note)
VALUES (axiom.db_fingerprint(), 'migration 0004', 'initial installation fingerprint');

CREATE TABLE axiom.jobs (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]*$'),
  handler_version int NOT NULL CHECK (handler_version >= 1),
  state text NOT NULL CHECK (state IN ('queued', 'running', 'waiting', 'succeeded', 'failed', 'dead_lettered',
                                       'cancelled', 'needs_operator')),
  dedupe_key text,
  payload jsonb NOT NULL,              -- identifiers only; never evidence content or secrets
  result jsonb,
  aggregate_type text,
  aggregate_id uuid,
  due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  attempts int NOT NULL DEFAULT 0,     -- step executions that reached the handler
  max_attempts int NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
  claims int NOT NULL DEFAULT 0,       -- every claim, including ones that crashed before the handler
  max_claims int NOT NULL DEFAULT 10 CHECK (max_claims BETWEEN 1 AND 1000),
  lease_owner text,
  lease_token bigint NOT NULL DEFAULT 0,
  lease_expires_at timestamptz,
  step_deadline_at timestamptz,
  cancel_requested boolean NOT NULL DEFAULT false,
  -- fingerprint under which the job was enqueued or last reconciled; a job carried across a restore
  -- cannot prove whether its effect already ran, so no-lookup effects park for an operator
  db_fingerprint text NOT NULL DEFAULT axiom.db_fingerprint(),
  wait_reason text,
  last_error text,
  operator_reason text,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  CHECK ((state IN ('succeeded', 'failed', 'dead_lettered', 'cancelled')) = (finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX jobs_dedupe ON axiom.jobs(tenant_id, kind, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX jobs_ready ON axiom.jobs(tenant_id, due_at) WHERE state IN ('queued', 'waiting', 'running');
CREATE INDEX jobs_aggregate ON axiom.jobs(tenant_id, aggregate_type, aggregate_id);

CREATE FUNCTION axiom.jobs_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'queued' OR NEW.lease_token <> 0 OR NEW.claims <> 0 OR NEW.attempts <> 0 THEN
      RAISE EXCEPTION 'jobs are created queued and unclaimed' USING ERRCODE = '23514';
    END IF;
    IF NEW.db_fingerprint <> axiom.db_fingerprint() THEN
      RAISE EXCEPTION 'job fingerprint must be the current database fingerprint' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.db_fingerprint IS DISTINCT FROM OLD.db_fingerprint AND NEW.db_fingerprint <> axiom.db_fingerprint() THEN
    RAISE EXCEPTION 'job fingerprint can only be set to the current database fingerprint' USING ERRCODE = '23514';
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.kind, NEW.payload, NEW.created_by, NEW.created_at, NEW.dedupe_key,
      NEW.aggregate_type, NEW.aggregate_id)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.kind, OLD.payload, OLD.created_by, OLD.created_at, OLD.dedupe_key,
      OLD.aggregate_type, OLD.aggregate_id) THEN
    RAISE EXCEPTION 'job definition is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('succeeded', 'failed', 'dead_lettered', 'cancelled') THEN
    RAISE EXCEPTION 'finished job is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.lease_token < OLD.lease_token OR NEW.claims < OLD.claims THEN
    RAISE EXCEPTION 'lease token and claim counter cannot decrease' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'job record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  -- Handler version changes only through an explicit migration of a job that is not running.
  IF NEW.handler_version <> OLD.handler_version AND OLD.state = 'running' THEN
    RAISE EXCEPTION 'cannot migrate a running job' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER jobs_guard BEFORE INSERT OR UPDATE ON axiom.jobs FOR EACH ROW EXECUTE FUNCTION axiom.jobs_guard();
CREATE TRIGGER jobs_no_delete BEFORE DELETE ON axiom.jobs FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.job_events (
  tenant_id uuid NOT NULL,
  job_id uuid NOT NULL,
  id uuid NOT NULL,
  event text NOT NULL,
  lease_token bigint,
  worker text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, job_id) REFERENCES axiom.jobs(tenant_id, id)
);
CREATE INDEX job_events_job ON axiom.job_events(tenant_id, job_id, created_at);
CREATE TRIGGER job_events_append_only BEFORE UPDATE OR DELETE ON axiom.job_events
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.effect_intents (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  job_id uuid NOT NULL,
  integration text NOT NULL CHECK (integration ~ '^[a-z0-9_]+$'),
  operation_key text NOT NULL CHECK (operation_key ~ '^[0-9a-f]{64}$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  lookup_supported boolean NOT NULL,
  state text NOT NULL CHECK (state IN ('prepared', 'executing', 'succeeded', 'unknown', 'failed', 'abandoned',
                                       'reconciled')),
  lease_token bigint NOT NULL,
  db_fingerprint text NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  external_ref text,
  last_error text,
  resolution text,
  resolved_by uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, operation_key),
  FOREIGN KEY (tenant_id, job_id) REFERENCES axiom.jobs(tenant_id, id),
  CHECK (state NOT IN ('succeeded', 'reconciled') OR external_ref IS NOT NULL)
);

CREATE FUNCTION axiom.effect_intents_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.job_id, NEW.integration, NEW.operation_key, NEW.request_digest,
      NEW.lookup_supported, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.job_id, OLD.integration, OLD.operation_key, OLD.request_digest,
      OLD.lookup_supported, OLD.created_at) THEN
    RAISE EXCEPTION 'effect intent identity is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('succeeded', 'failed', 'abandoned', 'reconciled') THEN
    RAISE EXCEPTION 'resolved effect intent is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.db_fingerprint IS DISTINCT FROM OLD.db_fingerprint AND NEW.db_fingerprint <> axiom.db_fingerprint() THEN
    RAISE EXCEPTION 'intent fingerprint can only be set to the current database fingerprint' USING ERRCODE = '23514';
  END IF;
  IF NOT ((OLD.state, NEW.state) IN (
      ('prepared', 'prepared'), ('prepared', 'executing'), ('prepared', 'failed'), ('prepared', 'abandoned'),
      ('prepared', 'reconciled'),
      ('executing', 'succeeded'), ('executing', 'failed'), ('executing', 'unknown'), ('executing', 'executing'),
      ('executing', 'prepared'),   -- the integration reported the request was definitely not applied
      ('executing', 'reconciled'),
      ('unknown', 'reconciled'), ('unknown', 'executing'), ('unknown', 'abandoned'), ('unknown', 'unknown'),
      ('unknown', 'prepared'))) THEN   -- operator confirmed the effect was not applied
    RAISE EXCEPTION 'effect intent % -> % not permitted', OLD.state, NEW.state USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'effect intent record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER effect_intents_guard BEFORE UPDATE ON axiom.effect_intents
  FOR EACH ROW EXECUTE FUNCTION axiom.effect_intents_guard();
CREATE TRIGGER effect_intents_no_delete BEFORE DELETE ON axiom.effect_intents
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('job.read', false, 'Read job state and history'),
 ('job.operate', true, 'Resolve jobs and effects that need an operator');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'job.read'), ('auditor', 'job.read'), ('policy_admin', 'job.read'), ('policy_admin', 'job.operate'),
 ('ingestion_worker', 'job.read');

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY['jobs', 'job_events', 'effect_intents']) AS t;
GRANT SELECT, INSERT ON axiom.jobs, axiom.job_events, axiom.effect_intents TO axiom_runtime;
GRANT UPDATE (handler_version, state, result, due_at, attempts, claims, lease_owner, lease_token, lease_expires_at,
  step_deadline_at, cancel_requested, db_fingerprint, wait_reason, last_error, operator_reason, updated_at,
  finished_at, record_version) ON axiom.jobs TO axiom_runtime;
GRANT UPDATE (state, lease_token, db_fingerprint, attempts, external_ref, last_error, resolution, resolved_by,
  updated_at, record_version) ON axiom.effect_intents TO axiom_runtime;

-- Installation operators (provisioning CLI) can see which effects are uncertain after a restore, across tenants,
-- without reading request content (only identifiers, state and fingerprint columns).
GRANT SELECT (tenant_id, id, job_id, integration, state, db_fingerprint, updated_at) ON axiom.effect_intents
  TO axiom_provisioner;
CREATE POLICY prov_effect_intents_read ON axiom.effect_intents FOR SELECT TO axiom_provisioner USING (true);
