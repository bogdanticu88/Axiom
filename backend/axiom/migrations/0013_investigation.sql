-- 0013 Phase C: frozen evidence snapshots, model routes, investigation runs, steps, claims and reviews; decisions
-- cite snapshots and runs; workload principals cannot record consequential decisions or approvals; SLA pause
-- records; explicit evidence-metadata disclosure permissions. ADR 0012.

-- ---------------------------------------------------------------------------- helpers
-- Principal kind lookup for guards (the runtime role cannot read axiom.principals directly).
SET LOCAL ROLE axiom_authn;     -- axiom_auth functions are owned by axiom_authn, which may read axiom.principals (0001)
CREATE FUNCTION axiom_auth.principal_kind(p_principal uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$ SELECT kind FROM axiom.principals WHERE id = p_principal $$;
REVOKE ALL ON FUNCTION axiom_auth.principal_kind(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom_auth.principal_kind(uuid) TO axiom_runtime;
SET LOCAL ROLE axiom_owner;

-- ---------------------------------------------------------------------------- evidence snapshots
-- A snapshot freezes exactly which observation versions, runs, asset versions, business context and evidence an
-- assessment or investigation may rely on, with freshness at that moment, recorded contradictions and missing
-- information. Snapshots and members are append-only; later evidence produces a new snapshot.
CREATE TABLE axiom.evidence_snapshots (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  scope_id uuid NOT NULL,
  as_of timestamptz NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('investigation', 'assessment')),
  freshness_policy_version_id uuid,
  member_count int NOT NULL CHECK (member_count >= 0),
  max_classification text CHECK (max_classification IN ('internal', 'confidential', 'restricted')),
  contradictions jsonb NOT NULL CHECK (jsonb_typeof(contradictions) = 'array'),
  gaps jsonb NOT NULL CHECK (jsonb_typeof(gaps) = 'array'),
  digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  FOREIGN KEY (tenant_id, freshness_policy_version_id) REFERENCES axiom.policy_versions(tenant_id, id)
);
CREATE INDEX evidence_snapshots_case ON axiom.evidence_snapshots(tenant_id, case_id, created_at);
CREATE TRIGGER evidence_snapshots_append_only BEFORE UPDATE OR DELETE ON axiom.evidence_snapshots
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.evidence_snapshot_members (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  member_key text NOT NULL CHECK (member_key ~ '^M[0-9]{3,5}$'),
  kind text NOT NULL CHECK (kind IN ('occurrence', 'occurrence_observation', 'observation', 'ingestion_run', 'asset',
                                     'asset_version', 'business_context', 'evidence_object')),
  ref_id uuid NOT NULL,
  ref_digest text,                       -- version identity where the source has one (observation, evidence digest)
  classification text CHECK (classification IN ('internal', 'confidential', 'restricted')),
  collected_at timestamptz,
  freshness text NOT NULL CHECK (freshness IN ('fresh', 'stale', 'unknown', 'not_applicable')),
  available boolean NOT NULL,            -- e.g. evidence verified and readable at snapshot time
  attributes jsonb NOT NULL CHECK (jsonb_typeof(attributes) = 'object'),
  PRIMARY KEY (tenant_id, snapshot_id, member_key),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES axiom.evidence_snapshots(tenant_id, id)
);
CREATE INDEX evidence_snapshot_members_ref ON axiom.evidence_snapshot_members(tenant_id, ref_id);
CREATE TRIGGER evidence_snapshot_members_append_only BEFORE UPDATE OR DELETE ON axiom.evidence_snapshot_members
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

ALTER TABLE axiom.decisions ADD CONSTRAINT decisions_evidence_snapshot
  FOREIGN KEY (tenant_id, evidence_snapshot_id) REFERENCES axiom.evidence_snapshots(tenant_id, id);

-- ---------------------------------------------------------------------------- model routes
-- An approved provider/model/destination per tenant. Proposed by one administrator, approved by another. The
-- definition is immutable; only the status changes. A run is bound to exactly one route (no fallback).
CREATE TABLE axiom.model_routes (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
  provider text NOT NULL CHECK (provider IN ('deterministic_fake', 'anthropic_messages')),
  model text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
  endpoint text NOT NULL CHECK (endpoint ~ '^(https://[a-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?|fake://[a-z0-9-]+)$'),
  region text NOT NULL CHECK (length(region) BETWEEN 1 AND 100),
  max_classification text NOT NULL CHECK (max_classification IN ('internal', 'confidential', 'restricted')),
  credential_ref text CHECK (credential_ref IS NULL OR credential_ref ~ '^secretref:[A-Za-z0-9/_.-]+$'),
  input_price_micros_per_mtok bigint NOT NULL DEFAULT 0 CHECK (input_price_micros_per_mtok >= 0),
  output_price_micros_per_mtok bigint NOT NULL DEFAULT 0 CHECK (output_price_micros_per_mtok >= 0),
  timeout_seconds int NOT NULL DEFAULT 60 CHECK (timeout_seconds BETWEEN 1 AND 600),
  max_retries int NOT NULL DEFAULT 1 CHECK (max_retries BETWEEN 0 AND 3),
  max_output_tokens int NOT NULL DEFAULT 4096 CHECK (max_output_tokens BETWEEN 1 AND 64000),
  status text NOT NULL CHECK (status IN ('proposed', 'approved', 'disabled')),
  rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
  proposed_by uuid NOT NULL,
  approved_by uuid,
  approved_at timestamptz,
  disabled_by uuid,
  disabled_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name),
  CHECK (approved_by IS NULL OR approved_by <> proposed_by),
  CHECK ((status = 'proposed') = (approved_by IS NULL) OR status = 'disabled'),
  CHECK ((provider = 'deterministic_fake') = (endpoint LIKE 'fake://%'))
);

CREATE FUNCTION axiom.model_routes_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'proposed' THEN
      RAISE EXCEPTION 'model routes are created as proposals' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.name, NEW.provider, NEW.model, NEW.endpoint, NEW.region, NEW.max_classification,
      NEW.credential_ref, NEW.input_price_micros_per_mtok, NEW.output_price_micros_per_mtok, NEW.timeout_seconds,
      NEW.max_retries, NEW.max_output_tokens, NEW.rationale, NEW.proposed_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.name, OLD.provider, OLD.model, OLD.endpoint, OLD.region, OLD.max_classification,
      OLD.credential_ref, OLD.input_price_micros_per_mtok, OLD.output_price_micros_per_mtok, OLD.timeout_seconds,
      OLD.max_retries, OLD.max_output_tokens, OLD.rationale, OLD.proposed_by, OLD.created_at) THEN
    RAISE EXCEPTION 'model route definitions are immutable; propose a new route' USING ERRCODE = '42501';
  END IF;
  IF NOT ((OLD.status, NEW.status) IN (('proposed', 'approved'), ('proposed', 'disabled'), ('approved', 'disabled'))) THEN
    RAISE EXCEPTION 'model route % -> % not permitted', OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'model route record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER model_routes_guard BEFORE INSERT OR UPDATE ON axiom.model_routes
  FOR EACH ROW EXECUTE FUNCTION axiom.model_routes_guard();
CREATE TRIGGER model_routes_no_delete BEFORE DELETE ON axiom.model_routes FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- investigation runs
CREATE TABLE axiom.investigation_runs (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  route_id uuid NOT NULL,
  route_binding jsonb NOT NULL,          -- provider, model, endpoint, region, max_classification frozen at creation
  questions jsonb NOT NULL CHECK (jsonb_typeof(questions) = 'array' AND jsonb_array_length(questions) BETWEEN 1 AND 10),
  tool_grants jsonb NOT NULL CHECK (jsonb_typeof(tool_grants) = 'array'),
  budget jsonb NOT NULL CHECK (jsonb_typeof(budget) = 'object'),
  deadline_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'incomplete', 'failed', 'cancelled')),
  outcome_reason text,
  model_calls int NOT NULL DEFAULT 0 CHECK (model_calls >= 0),
  tool_calls int NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
  input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  cost_micros bigint NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
  redactions int NOT NULL DEFAULT 0 CHECK (redactions >= 0),
  rounds int NOT NULL DEFAULT 0 CHECK (rounds >= 0),
  next_checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
  requested_by uuid NOT NULL,
  job_id uuid,
  cancel_requested_at timestamptz,
  cancel_requested_by uuid,
  started_at timestamptz,
  ended_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES axiom.evidence_snapshots(tenant_id, id),
  FOREIGN KEY (tenant_id, route_id) REFERENCES axiom.model_routes(tenant_id, id),
  CHECK ((status IN ('completed', 'incomplete', 'failed', 'cancelled')) = (ended_at IS NOT NULL)),
  CHECK (status NOT IN ('incomplete', 'failed', 'cancelled') OR outcome_reason IS NOT NULL)
);
CREATE INDEX investigation_runs_case ON axiom.investigation_runs(tenant_id, case_id, created_at);

CREATE FUNCTION axiom.investigation_runs_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.snapshot_id, NEW.route_id, NEW.route_binding, NEW.questions,
      NEW.tool_grants, NEW.budget, NEW.deadline_at, NEW.requested_by, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.case_id, OLD.snapshot_id, OLD.route_id, OLD.route_binding,
                       OLD.questions, OLD.tool_grants, OLD.budget, OLD.deadline_at, OLD.requested_by, OLD.created_at) THEN
    RAISE EXCEPTION 'investigation run terms are immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('completed', 'incomplete', 'failed', 'cancelled') THEN
    RAISE EXCEPTION 'finished investigation run is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.model_calls < OLD.model_calls OR NEW.tool_calls < OLD.tool_calls OR NEW.input_tokens < OLD.input_tokens
     OR NEW.output_tokens < OLD.output_tokens OR NEW.cost_micros < OLD.cost_micros OR NEW.rounds < OLD.rounds
     OR NEW.redactions < OLD.redactions THEN
    RAISE EXCEPTION 'investigation usage counters cannot decrease' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'investigation run record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER investigation_runs_guard BEFORE UPDATE ON axiom.investigation_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.investigation_runs_guard();
CREATE TRIGGER investigation_runs_no_delete BEFORE DELETE ON axiom.investigation_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Every model and tool call: what was asked (digest and a bounded, redacted summary), what came back, usage, latency.
-- A step left 'started' by a crashed worker is marked 'lost' on recovery and stays counted against the budget.
CREATE TABLE axiom.investigation_steps (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid NOT NULL,
  seq int NOT NULL CHECK (seq >= 1),
  kind text NOT NULL CHECK (kind IN ('model', 'tool')),
  name text NOT NULL,
  destination text NOT NULL,
  status text NOT NULL CHECK (status IN ('started', 'completed', 'failed', 'lost', 'refused')),
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  response_digest text CHECK (response_digest ~ '^[0-9a-f]{64}$'),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempt int NOT NULL DEFAULT 1 CHECK (attempt >= 1),
  input_tokens bigint NOT NULL DEFAULT 0,
  output_tokens bigint NOT NULL DEFAULT 0,
  cost_micros bigint NOT NULL DEFAULT 0,
  latency_ms int,
  error text,
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, run_id, seq),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.investigation_runs(tenant_id, id),
  CHECK ((status = 'started') = (ended_at IS NULL))
);

CREATE FUNCTION axiom.investigation_steps_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.status <> 'started' THEN
    RAISE EXCEPTION 'finished investigation step is immutable' USING ERRCODE = '23514';
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.run_id, NEW.seq, NEW.kind, NEW.name, NEW.destination, NEW.request_digest,
      NEW.attempt, NEW.started_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.run_id, OLD.seq, OLD.kind, OLD.name, OLD.destination,
                       OLD.request_digest, OLD.attempt, OLD.started_at) THEN
    RAISE EXCEPTION 'investigation step identity is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER investigation_steps_guard BEFORE UPDATE ON axiom.investigation_steps
  FOR EACH ROW EXECUTE FUNCTION axiom.investigation_steps_guard();
CREATE TRIGGER investigation_steps_no_delete BEFORE DELETE ON axiom.investigation_steps
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- claims and reviews
CREATE TABLE axiom.investigation_claims (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid NOT NULL,
  case_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  seq int NOT NULL CHECK (seq >= 1),
  question_id text NOT NULL,
  statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 2000),
  subject jsonb NOT NULL CHECK (jsonb_typeof(subject) = 'object'),
  proposed_conclusion text NOT NULL CHECK (proposed_conclusion IN ('supported', 'contradicted', 'unknown')),
  accepted_conclusion text CHECK (accepted_conclusion IN ('supported', 'contradicted', 'unknown')),
  validation text NOT NULL CHECK (validation IN ('references_checked', 'downgraded', 'rejected')),
  validation_reasons jsonb NOT NULL CHECK (jsonb_typeof(validation_reasons) = 'array'),
  limitations text,
  model_stated_confidence text CHECK (model_stated_confidence IN ('low', 'medium', 'high')),  -- uncalibrated label
  entailment text NOT NULL DEFAULT 'not_verified' CHECK (entailment = 'not_verified'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, run_id, seq),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.investigation_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES axiom.evidence_snapshots(tenant_id, id),
  CHECK ((validation = 'rejected') = (accepted_conclusion IS NULL))
);
CREATE TRIGGER investigation_claims_append_only BEFORE UPDATE OR DELETE ON axiom.investigation_claims
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Only references that resolve to a member of the claim's own snapshot can be stored (fabricated or foreign
-- references are recorded in validation_reasons of a rejected claim instead).
CREATE TABLE axiom.claim_references (
  tenant_id uuid NOT NULL,
  claim_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  member_key text NOT NULL,
  relation text NOT NULL CHECK (relation IN ('supports', 'contradicts')),
  PRIMARY KEY (tenant_id, claim_id, member_key, relation),
  FOREIGN KEY (tenant_id, claim_id) REFERENCES axiom.investigation_claims(tenant_id, id),
  FOREIGN KEY (tenant_id, snapshot_id, member_key) REFERENCES axiom.evidence_snapshot_members(tenant_id, snapshot_id, member_key)
);
CREATE FUNCTION axiom.claim_references_same_snapshot() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM axiom.investigation_claims c WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.claim_id
                    AND c.snapshot_id = NEW.snapshot_id AND c.validation <> 'rejected') THEN
    RAISE EXCEPTION 'claim reference must point into the claim''s own snapshot' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER claim_references_same_snapshot BEFORE INSERT ON axiom.claim_references
  FOR EACH ROW EXECUTE FUNCTION axiom.claim_references_same_snapshot();
CREATE TRIGGER claim_references_append_only BEFORE UPDATE OR DELETE ON axiom.claim_references
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.claim_reviews (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  claim_id uuid NOT NULL,
  run_id uuid NOT NULL,
  verdict text NOT NULL CHECK (verdict IN ('confirmed', 'rejected', 'corrected')),
  corrected_conclusion text CHECK (corrected_conclusion IN ('supported', 'contradicted', 'unknown')),
  note text NOT NULL CHECK (length(btrim(note)) > 0),
  reviewer uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, claim_id) REFERENCES axiom.investigation_claims(tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES axiom.investigation_runs(tenant_id, id),
  CHECK ((verdict = 'corrected') = (corrected_conclusion IS NOT NULL))
);
CREATE TRIGGER claim_reviews_append_only BEFORE UPDATE OR DELETE ON axiom.claim_reviews
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

ALTER TABLE axiom.decisions ADD COLUMN investigation_run_id uuid;
ALTER TABLE axiom.decisions ADD CONSTRAINT decisions_investigation_run
  FOREIGN KEY (tenant_id, investigation_run_id) REFERENCES axiom.investigation_runs(tenant_id, id);

-- ---------------------------------------------------------------------------- authority backstops
-- Workload principals (the tenant system principal that runs ingestion, sweeps and investigations) may record only
-- recurrence/expiry reopenings and deterministic prioritisation. Assessments, dismissals, closures, risk acceptance,
-- verification and every other consequential decision need a human; so do approvals and claim reviews.
CREATE FUNCTION axiom.human_decision_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  actor uuid;
  allowed boolean := false;
BEGIN
  -- separate branches: a record field that does not exist on this table must not be referenced
  IF TG_TABLE_NAME = 'decisions' THEN
    actor := NEW.actor_principal_id;
    allowed := NEW.kind IN ('reopen', 'prioritisation');
  ELSIF TG_TABLE_NAME = 'approvals' THEN
    actor := NEW.approver_principal_id;
  ELSE
    actor := NEW.reviewer;
  END IF;
  IF axiom_auth.principal_kind(actor) IS DISTINCT FROM 'human' AND NOT allowed THEN
    RAISE EXCEPTION '% by a non-human principal is not permitted', TG_TABLE_NAME USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER decisions_human_guard BEFORE INSERT ON axiom.decisions
  FOR EACH ROW EXECUTE FUNCTION axiom.human_decision_guard();
CREATE TRIGGER approvals_human_guard BEFORE INSERT ON axiom.approvals
  FOR EACH ROW EXECUTE FUNCTION axiom.human_decision_guard();
CREATE TRIGGER claim_reviews_human_guard BEFORE INSERT ON axiom.claim_reviews
  FOR EACH ROW EXECUTE FUNCTION axiom.human_decision_guard();

-- ---------------------------------------------------------------------------- SLA pause records
-- Each pause interval with its authorised reason and who recorded the deferral (gross vs adjusted time, ADR 0011).
ALTER TABLE axiom.sla_timers ADD COLUMN pauses jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(pauses) = 'array');
GRANT UPDATE (pauses) ON axiom.sla_timers TO axiom_runtime;

-- ---------------------------------------------------------------------------- permissions, RLS, grants
INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('snapshot.create', false, 'Freeze an evidence snapshot for a case'),
 ('investigation.run', false, 'Start an investigation run on a case'),
 ('investigation.read', false, 'Read investigation runs, steps and claims'),
 ('investigation.cancel', false, 'Cancel an investigation run'),
 ('investigation.review', false, 'Review investigation claims'),
 ('model.configure', false, 'Propose or disable a model route'),
 ('model.approve', true, 'Approve a model route for the tenant'),
 ('evidence.metadata:internal', false, 'See digests, sizes and filenames of internal evidence without its content'),
 ('evidence.metadata:confidential', false, 'See digests, sizes and filenames of confidential evidence without its content'),
 ('evidence.metadata:restricted', true, 'See digests, sizes and filenames of restricted evidence without its content');
INSERT INTO axiom.roles(id, description) VALUES
 ('evidence_metadata_reader', 'Explicit disclosure of evidence metadata (digest, size, filename) for internal and confidential evidence');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'snapshot.create'), ('analyst', 'investigation.run'), ('analyst', 'investigation.read'),
 ('analyst', 'investigation.cancel'), ('analyst', 'investigation.review'), ('auditor', 'investigation.read'),
 ('policy_admin', 'model.configure'), ('policy_admin', 'model.approve'),
 ('evidence_metadata_reader', 'evidence.metadata:internal'), ('evidence_metadata_reader', 'evidence.metadata:confidential')
ON CONFLICT DO NOTHING;

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY['evidence_snapshots', 'evidence_snapshot_members', 'model_routes',
  'investigation_runs', 'investigation_steps', 'investigation_claims', 'claim_references', 'claim_reviews']) AS t;
GRANT SELECT, INSERT ON axiom.evidence_snapshots, axiom.evidence_snapshot_members, axiom.model_routes, axiom.investigation_runs,
  axiom.investigation_steps, axiom.investigation_claims, axiom.claim_references, axiom.claim_reviews TO axiom_runtime;
GRANT UPDATE (status, approved_by, approved_at, disabled_by, disabled_at, record_version) ON axiom.model_routes TO axiom_runtime;
GRANT UPDATE (status, outcome_reason, model_calls, tool_calls, input_tokens, output_tokens, cost_micros, redactions,
  rounds, next_checks, limitations, job_id, cancel_requested_at, cancel_requested_by, started_at, ended_at,
  record_version) ON axiom.investigation_runs TO axiom_runtime;
GRANT UPDATE (status, response_digest, detail, input_tokens, output_tokens, cost_micros, latency_ms, error, ended_at)
  ON axiom.investigation_steps TO axiom_runtime;
