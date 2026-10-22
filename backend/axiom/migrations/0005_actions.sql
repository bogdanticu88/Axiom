-- 0005 Action and approval protocol (Specification S 9, Implementation Plan S 7, Data and Access Design S 7).
--
--   action_proposals          stable identity, status and current version of a proposal
--   action_proposal_versions  immutable versions; the database computes the binding digest
--   approvals                 bound to one proposal version and its digest; expiry; use counts; revocation
--   approval_reservations     one row per reserved use, created under a lock on the approval row
--   action_executions         one execution per reservation, with a stable external operation identity
--   external_references       verified links to external objects (tickets)
--   idempotency_keys          API idempotency (tenant, principal, endpoint, key) with request digest and response
--
-- Database guards here are row-local or reference one parent row. Cross-record authority checks (current role
-- bindings, delegation, preconditions) are in the service and re-run before the effect.

-- ---------------------------------------------------------------------------- proposals
CREATE TABLE axiom.action_proposals (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  effect_class text NOT NULL CHECK (effect_class ~ '^[a-z][a-z0-9_.]*$'),
  scope_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('open', 'withdrawn', 'executed')),
  current_version int NOT NULL CHECK (current_version >= 1),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id)
);

CREATE TABLE axiom.action_proposal_versions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  proposal_id uuid NOT NULL,
  version int NOT NULL CHECK (version >= 1),
  effect_class text NOT NULL,
  scope_id uuid NOT NULL,
  case_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  resources jsonb NOT NULL CHECK (jsonb_typeof(resources) = 'array' AND jsonb_array_length(resources) >= 1),
  canonical_payload jsonb NOT NULL CHECK (jsonb_typeof(canonical_payload) = 'object'),
  preconditions jsonb NOT NULL CHECK (jsonb_typeof(preconditions) = 'object'),
  rollback_guidance text,
  verification_criteria text NOT NULL,
  owner_principal_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  payload_digest text NOT NULL,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, proposal_id, version),
  UNIQUE (tenant_id, id, payload_digest),
  FOREIGN KEY (tenant_id, proposal_id) REFERENCES axiom.action_proposals(tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id),
  FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  CHECK (expires_at > created_at)
);

-- The binding digest covers everything an approval authorises. jsonb has a canonical text form (keys ordered,
-- whitespace normalised), so the digest is reproducible from the stored row.
CREATE FUNCTION axiom.proposal_binding_digest(v axiom.action_proposal_versions) RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT encode(sha256(convert_to(jsonb_build_object(
    'tenant_id', v.tenant_id, 'proposal_id', v.proposal_id, 'version', v.version,
    'effect_class', v.effect_class, 'scope_id', v.scope_id, 'case_id', v.case_id,
    'connection_id', v.connection_id, 'resources', v.resources, 'payload', v.canonical_payload,
    'preconditions', v.preconditions, 'expires_at', to_char(v.expires_at AT TIME ZONE 'UTC',
                                                             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  )::text, 'UTF8')), 'hex')
$$;

CREATE FUNCTION axiom.proposal_version_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE p axiom.action_proposals;
BEGIN
  SELECT * INTO p FROM axiom.action_proposals WHERE tenant_id = NEW.tenant_id AND id = NEW.proposal_id;
  IF p.effect_class <> NEW.effect_class OR p.scope_id <> NEW.scope_id OR p.case_id <> NEW.case_id THEN
    RAISE EXCEPTION 'proposal version must keep the proposal''s effect class, scope and case' USING ERRCODE = '23514';
  END IF;
  IF p.status <> 'open' THEN
    RAISE EXCEPTION 'proposal is not open' USING ERRCODE = '23514';
  END IF;
  NEW.payload_digest := axiom.proposal_binding_digest(NEW);   -- never trusted from the client or the service
  RETURN NEW;
END
$$;
CREATE TRIGGER proposal_version_insert BEFORE INSERT ON axiom.action_proposal_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.proposal_version_insert();
CREATE TRIGGER proposal_versions_immutable BEFORE UPDATE OR DELETE ON axiom.action_proposal_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE FUNCTION axiom.action_proposals_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.effect_class, NEW.scope_id, NEW.created_by, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.case_id, OLD.effect_class, OLD.scope_id, OLD.created_by,
                       OLD.created_at) THEN
    RAISE EXCEPTION 'proposal identity is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'open' THEN
    RAISE EXCEPTION 'withdrawn or executed proposal is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.current_version NOT IN (OLD.current_version, OLD.current_version + 1) THEN
    RAISE EXCEPTION 'proposal versions advance one at a time' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'proposal record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER action_proposals_guard BEFORE UPDATE ON axiom.action_proposals
  FOR EACH ROW EXECUTE FUNCTION axiom.action_proposals_guard();
CREATE TRIGGER action_proposals_no_delete BEFORE DELETE ON axiom.action_proposals
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- approvals
CREATE TABLE axiom.approvals (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  proposal_id uuid NOT NULL,
  proposal_version_id uuid NOT NULL,
  payload_digest text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
  approver_principal_id uuid NOT NULL,
  authorised_scope_id uuid NOT NULL,   -- the scope of the role binding that granted action.approve
  authority_snapshot jsonb NOT NULL,
  rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
  valid_until timestamptz NOT NULL,
  max_uses int NOT NULL CHECK (max_uses BETWEEN 1 AND 100),
  uses_reserved int NOT NULL DEFAULT 0,
  uses_released int NOT NULL DEFAULT 0,
  status text NOT NULL CHECK (status IN ('active', 'rejected', 'revoked')),
  revoked_at timestamptz,
  revoked_by uuid,
  revocation_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  -- the digest is part of the reference: an approval cannot point at a version whose digest differs
  FOREIGN KEY (tenant_id, proposal_version_id, payload_digest)
    REFERENCES axiom.action_proposal_versions(tenant_id, id, payload_digest),
  FOREIGN KEY (tenant_id, proposal_id) REFERENCES axiom.action_proposals(tenant_id, id),
  FOREIGN KEY (tenant_id, approver_principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, authorised_scope_id) REFERENCES axiom.scopes(tenant_id, id),
  CHECK (uses_released <= uses_reserved AND uses_reserved - uses_released <= max_uses),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK ((decision = 'rejected') = (status = 'rejected'))
);
CREATE UNIQUE INDEX approvals_one_decision_per_approver
  ON axiom.approvals(tenant_id, proposal_version_id, approver_principal_id);

CREATE FUNCTION axiom.approvals_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE v axiom.action_proposal_versions; p axiom.action_proposals;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO v FROM axiom.action_proposal_versions WHERE tenant_id = NEW.tenant_id AND id = NEW.proposal_version_id;
    SELECT * INTO p FROM axiom.action_proposals WHERE tenant_id = NEW.tenant_id AND id = NEW.proposal_id;
    IF v.proposal_id <> NEW.proposal_id THEN
      RAISE EXCEPTION 'approval proposal does not match the version' USING ERRCODE = '23514';
    END IF;
    IF p.current_version <> v.version OR p.status <> 'open' THEN
      RAISE EXCEPTION 'only the current version of an open proposal can be decided' USING ERRCODE = '23514';
    END IF;
    -- separation of duties, also enforced here so a service bug cannot bypass it
    IF NEW.approver_principal_id IN (v.created_by, p.created_by) THEN
      RAISE EXCEPTION 'proposers cannot approve their own proposals' USING ERRCODE = '42501';
    END IF;
    IF NEW.valid_until > v.expires_at THEN
      RAISE EXCEPTION 'approval cannot outlive the proposal version' USING ERRCODE = '23514';
    END IF;
    IF NEW.uses_reserved <> 0 OR NEW.uses_released <> 0 OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'approvals are created unused and unrevoked' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.proposal_id, NEW.proposal_version_id, NEW.payload_digest, NEW.decision,
      NEW.approver_principal_id, NEW.authorised_scope_id, NEW.authority_snapshot, NEW.rationale, NEW.valid_until,
      NEW.max_uses, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.proposal_id, OLD.proposal_version_id, OLD.payload_digest, OLD.decision,
      OLD.approver_principal_id, OLD.authorised_scope_id, OLD.authority_snapshot, OLD.rationale, OLD.valid_until,
      OLD.max_uses, OLD.created_at) THEN
    RAISE EXCEPTION 'approval binding is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('rejected', 'revoked') THEN
    RAISE EXCEPTION 'rejected or revoked approval is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.uses_reserved < OLD.uses_reserved OR NEW.uses_reserved > OLD.uses_reserved + 1
     OR NEW.uses_released < OLD.uses_released OR NEW.uses_released > OLD.uses_released + 1 THEN
    RAISE EXCEPTION 'approval use counters move forward one at a time' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'approval record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER approvals_guard BEFORE INSERT OR UPDATE ON axiom.approvals
  FOR EACH ROW EXECUTE FUNCTION axiom.approvals_guard();
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON axiom.approvals
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- reservations and executions
CREATE TABLE axiom.action_executions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  proposal_id uuid NOT NULL,
  proposal_version_id uuid NOT NULL,
  payload_digest text NOT NULL,
  approval_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  requested_by uuid NOT NULL,
  external_operation_id text NOT NULL CHECK (external_operation_id ~ '^[0-9a-f]{64}$'),
  job_id uuid,
  state text NOT NULL CHECK (state IN ('prepared', 'executing', 'reconciling', 'succeeded', 'failed', 'cancelled')),
  external_ref text,
  outcome_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, external_operation_id),
  FOREIGN KEY (tenant_id, proposal_version_id, payload_digest)
    REFERENCES axiom.action_proposal_versions(tenant_id, id, payload_digest),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES axiom.approvals(tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id),
  FOREIGN KEY (tenant_id, job_id) REFERENCES axiom.jobs(tenant_id, id),
  CHECK (state <> 'succeeded' OR external_ref IS NOT NULL)
);

CREATE TABLE axiom.approval_reservations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  approval_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  use_number int NOT NULL CHECK (use_number >= 1),
  status text NOT NULL CHECK (status IN ('reserved', 'consumed', 'released')),
  release_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, approval_id, use_number),
  UNIQUE (tenant_id, execution_id),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES axiom.approvals(tenant_id, id),
  FOREIGN KEY (tenant_id, execution_id) REFERENCES axiom.action_executions(tenant_id, id) DEFERRABLE INITIALLY DEFERRED,
  CHECK ((status = 'released') = (release_reason IS NOT NULL))
);

CREATE FUNCTION axiom.approval_reservations_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE a axiom.approvals; e axiom.action_executions;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO a FROM axiom.approvals WHERE tenant_id = NEW.tenant_id AND id = NEW.approval_id;
    -- the reservation must correspond to the counter increment made in the same transaction
    IF NEW.status <> 'reserved' OR NEW.use_number <> a.uses_reserved THEN
      RAISE EXCEPTION 'reservation must match the approval use counter' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.approval_id, NEW.execution_id, NEW.use_number, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.approval_id, OLD.execution_id, OLD.use_number, OLD.created_at) THEN
    RAISE EXCEPTION 'reservation identity is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'reserved' THEN
    RAISE EXCEPTION 'consumed or released reservation is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.status = 'released' THEN
    -- a use is returned only if the effect was never attempted: timeouts never restore a use blindly
    SELECT * INTO e FROM axiom.action_executions WHERE tenant_id = NEW.tenant_id AND id = NEW.execution_id;
    IF e.state NOT IN ('cancelled', 'failed') OR EXISTS (
         SELECT 1 FROM axiom.effect_intents i WHERE i.tenant_id = NEW.tenant_id
            AND i.operation_key = e.external_operation_id AND i.state <> 'prepared') THEN
      RAISE EXCEPTION 'a use can be released only when the effect was never attempted' USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'reservation record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER approval_reservations_guard BEFORE INSERT OR UPDATE ON axiom.approval_reservations
  FOR EACH ROW EXECUTE FUNCTION axiom.approval_reservations_guard();
CREATE TRIGGER approval_reservations_no_delete BEFORE DELETE ON axiom.approval_reservations
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE FUNCTION axiom.action_executions_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE a axiom.approvals;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO a FROM axiom.approvals WHERE tenant_id = NEW.tenant_id AND id = NEW.approval_id;
    IF a.proposal_version_id <> NEW.proposal_version_id OR a.payload_digest <> NEW.payload_digest
       OR a.status <> 'active' OR a.decision <> 'approved' THEN
      RAISE EXCEPTION 'execution requires an active approval of this exact proposal version' USING ERRCODE = '23514';
    END IF;
    IF NEW.state <> 'prepared' THEN
      RAISE EXCEPTION 'executions are created prepared' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.proposal_id, NEW.proposal_version_id, NEW.payload_digest, NEW.approval_id,
      NEW.connection_id, NEW.requested_by, NEW.external_operation_id, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.proposal_id, OLD.proposal_version_id, OLD.payload_digest, OLD.approval_id,
      OLD.connection_id, OLD.requested_by, OLD.external_operation_id, OLD.created_at) THEN
    RAISE EXCEPTION 'execution identity is immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id THEN
    RAISE EXCEPTION 'execution job is immutable once set' USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('succeeded', 'failed', 'cancelled') THEN
    RAISE EXCEPTION 'finished execution is immutable' USING ERRCODE = '23514';
  END IF;
  IF NOT ((OLD.state, NEW.state) IN (
      ('prepared', 'prepared'), ('prepared', 'executing'), ('prepared', 'cancelled'), ('prepared', 'failed'),
      ('prepared', 'succeeded'), ('prepared', 'reconciling'),
      ('executing', 'executing'), ('executing', 'succeeded'), ('executing', 'failed'), ('executing', 'reconciling'),
      ('executing', 'prepared'), ('executing', 'cancelled'),
      ('reconciling', 'reconciling'), ('reconciling', 'succeeded'), ('reconciling', 'failed'),
      ('reconciling', 'executing'), ('reconciling', 'prepared'))) THEN
    RAISE EXCEPTION 'execution % -> % not permitted', OLD.state, NEW.state USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'execution record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER action_executions_guard BEFORE INSERT OR UPDATE ON axiom.action_executions
  FOR EACH ROW EXECUTE FUNCTION axiom.action_executions_guard();
CREATE TRIGGER action_executions_no_delete BEFORE DELETE ON axiom.action_executions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.external_references (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  execution_id uuid NOT NULL,
  case_id uuid NOT NULL,
  provider text NOT NULL,
  connection_id uuid NOT NULL,
  external_id text NOT NULL,
  verified boolean NOT NULL,
  how text NOT NULL CHECK (how IN ('created', 'adopted_by_lookup', 'adopted_by_operator')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, execution_id),
  UNIQUE (tenant_id, provider, connection_id, external_id),
  FOREIGN KEY (tenant_id, execution_id) REFERENCES axiom.action_executions(tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id)
);
CREATE TRIGGER external_references_append_only BEFORE UPDATE OR DELETE ON axiom.external_references
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- idempotency keys (API-07)
CREATE TABLE axiom.idempotency_keys (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  principal_id uuid NOT NULL,
  endpoint text NOT NULL,
  key text NOT NULL CHECK (key ~ '^[A-Za-z0-9._:-]{8,128}$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('in_progress', 'completed')),
  response_status int,
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, principal_id, endpoint, key),
  CHECK ((status = 'completed') = (response_status IS NOT NULL))
);
CREATE FUNCTION axiom.idempotency_keys_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.principal_id, NEW.endpoint, NEW.key, NEW.request_digest, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.principal_id, OLD.endpoint, OLD.key, OLD.request_digest, OLD.created_at)
     OR OLD.status = 'completed' THEN
    RAISE EXCEPTION 'idempotency records are written once' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER idempotency_keys_guard BEFORE UPDATE ON axiom.idempotency_keys
  FOR EACH ROW EXECUTE FUNCTION axiom.idempotency_keys_guard();

-- ---------------------------------------------------------------------------- effect intent capabilities
-- What the integration can do to make retries safe, recorded with each intent (ADR 0010).
ALTER TABLE axiom.effect_intents
  ADD COLUMN dedupe text NOT NULL DEFAULT 'none' CHECK (dedupe IN ('none', 'idempotency_key', 'unique_external_id')),
  ADD COLUMN lookup text NOT NULL DEFAULT 'none' CHECK (lookup IN ('none', 'strong', 'eventual')),
  ADD COLUMN provider_fencing boolean NOT NULL DEFAULT false,
  ADD COLUMN effect_watermark bigint;
GRANT UPDATE (effect_watermark) ON axiom.effect_intents TO axiom_runtime;

-- Effect watermark (ADR 0010): drawn in the transaction that marks an intent executing. Sequences are not rolled
-- back with a failed transaction, so in normal operation the database value is always >= anything recorded outside
-- it. A database that is rolled back or restored to an earlier state shows a lower value than an external witness.
CREATE SEQUENCE axiom.effect_watermark_seq AS bigint MINVALUE 1 START WITH 1;
GRANT USAGE, SELECT ON SEQUENCE axiom.effect_watermark_seq TO axiom_runtime;
GRANT SELECT, UPDATE ON SEQUENCE axiom.effect_watermark_seq TO axiom_provisioner;   -- setval on acknowledged recovery

-- ---------------------------------------------------------------------------- permissions, RLS, grants
INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('action.propose', false, 'Propose external actions for cases in scope'),
 ('action.execute', false, 'Request execution of an approved action'),
 ('action.reconcile', true, 'Resolve external actions whose outcome is uncertain');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'action.propose'), ('analyst', 'action.execute'), ('analyst', 'proposal.read'),
 ('auditor', 'proposal.read'), ('policy_admin', 'action.reconcile'), ('policy_admin', 'proposal.read');

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY['action_proposals', 'action_proposal_versions', 'approvals',
  'approval_reservations', 'action_executions', 'external_references', 'idempotency_keys']) AS t;
GRANT SELECT, INSERT ON axiom.action_proposals, axiom.action_proposal_versions, axiom.approvals, axiom.approval_reservations,
  axiom.action_executions, axiom.external_references, axiom.idempotency_keys TO axiom_runtime;
GRANT UPDATE (status, current_version, record_version) ON axiom.action_proposals TO axiom_runtime;
GRANT UPDATE (uses_reserved, uses_released, status, revoked_at, revoked_by, revocation_reason, record_version)
  ON axiom.approvals TO axiom_runtime;
GRANT UPDATE (status, release_reason, record_version) ON axiom.approval_reservations TO axiom_runtime;
GRANT UPDATE (job_id, state, external_ref, outcome_detail, updated_at, record_version) ON axiom.action_executions
  TO axiom_runtime;
GRANT UPDATE (status, response_status, response_body) ON axiom.idempotency_keys TO axiom_runtime;
GRANT EXECUTE ON FUNCTION axiom.proposal_binding_digest(axiom.action_proposal_versions) TO axiom_runtime;
