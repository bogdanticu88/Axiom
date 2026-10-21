-- 0002 Case lifecycle: minimal assets/occurrences needed for deployment-bound
-- verification, finding cases, append-only events/decisions, remediation
-- reports, verification runs, risk acceptance and reason-specific closure.
--
-- Guards are enforced twice (docs/adr/0004-case-command-guards.md):
--   1. The application command layer (backend/axiom/domains/cases) loads
--      authoritative records and returns structured conflicts.
--   2. These triggers reject anything that bypasses the command layer:
--        * immediate: allowed transitions, version increments, immutable identity;
--        * deferred to COMMIT: every case write has a matching case_event that
--          references an audit_event, and every closure has a valid
--          reason-specific closure record.
-- Database triggers validate what the database can see. They do not replace
-- authorisation, and they cannot judge whether a rationale is sound.

-- ---------------------------------------------------------------------------
-- Assets (minimal; Phase B extends identity correlation)
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.assets (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  scope_id uuid NOT NULL,
  asset_kind text NOT NULL CHECK (asset_kind IN ('host', 'container_image', 'workload', 'cloud_resource',
                                                  'repository', 'application', 'unknown')),
  display_name text NOT NULL,
  lifecycle_status text NOT NULL DEFAULT 'active' CHECK (lifecycle_status IN ('active', 'retired', 'unknown')),
  retirement_evidence_id uuid,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  FOREIGN KEY (tenant_id, retirement_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  CHECK (lifecycle_status <> 'retired' OR retirement_evidence_id IS NOT NULL)
);
CREATE TRIGGER assets_identity BEFORE UPDATE ON axiom.assets
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_identity_change();

-- Observed, immutable deployment/version of an asset.
CREATE TABLE axiom.asset_versions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  asset_id uuid NOT NULL,
  deployment_digest text,          -- e.g. image digest; NULL when the source has none
  version_label text,
  observed_at timestamptz NOT NULL,
  source_evidence_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES axiom.assets(tenant_id, id),
  FOREIGN KEY (tenant_id, source_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  CHECK (deployment_digest IS NULL OR deployment_digest ~ '^[a-z0-9]+:[0-9a-f]{32,128}$')
);
CREATE INDEX asset_versions_digest ON axiom.asset_versions(tenant_id, deployment_digest);
CREATE TRIGGER asset_versions_append_only BEFORE UPDATE OR DELETE ON axiom.asset_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Scanner-specific finding on a specific asset version and component.
-- source_system/source_finding_id are replaced by a connection reference in Phase B.
CREATE TABLE axiom.finding_occurrences (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  source_system text NOT NULL,
  source_finding_id text NOT NULL,
  asset_version_id uuid NOT NULL,
  component_locator text NOT NULL DEFAULT '',
  vulnerability_ref text,          -- e.g. CVE; never an identity on its own
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, source_system, source_finding_id, asset_version_id, component_locator),
  FOREIGN KEY (tenant_id, asset_version_id) REFERENCES axiom.asset_versions(tenant_id, id)
);
CREATE TRIGGER finding_occurrences_append_only BEFORE UPDATE OR DELETE ON axiom.finding_occurrences
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Finding cases
-- ---------------------------------------------------------------------------
CREATE TABLE axiom.finding_cases (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  scope_id uuid NOT NULL,
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  workflow text NOT NULL CHECK (workflow IN ('received', 'investigating', 'review_required',
      'remediation_planned', 'remediating', 'awaiting_verification', 'closed')),
  assessment text NOT NULL CHECK (assessment IN ('unassessed', 'supported', 'not_supported', 'inconclusive')),
  priority text NOT NULL CHECK (priority IN ('pending', 'urgent', 'high', 'medium', 'low')),
  disposition text NOT NULL CHECK (disposition IN ('unset', 'remediate', 'accept_risk', 'defer', 'duplicate', 'dismiss')),
  owner_principal_id uuid,
  review_at timestamptz,
  record_version bigint NOT NULL CHECK (record_version >= 0),
  schema_version int NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  -- Deferral remains open with a review date.
  CHECK (disposition <> 'defer' OR (review_at IS NOT NULL AND workflow <> 'closed')),
  -- remediation_planned requires an owner.
  CHECK (workflow NOT IN ('remediation_planned', 'remediating', 'awaiting_verification')
         OR owner_principal_id IS NOT NULL)
);
CREATE INDEX finding_cases_queue ON axiom.finding_cases(tenant_id, scope_id, workflow, priority, review_at);

CREATE TABLE axiom.case_occurrence_links (
  tenant_id uuid NOT NULL,
  case_id uuid NOT NULL,
  occurrence_id uuid NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  linked_by uuid NOT NULL,
  unlinked_at timestamptz,
  unlinked_by uuid,
  PRIMARY KEY (tenant_id, case_id, occurrence_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, occurrence_id) REFERENCES axiom.finding_occurrences(tenant_id, id)
);

-- Authoritative append-only decision history.
CREATE TABLE axiom.decisions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('investigation_start', 'assessment', 'escalation', 'evidence_request',
      'remediation_plan', 'external_work', 'remediation_report', 'verification_review', 'deferral',
      'closure', 'reopen', 'owner_assignment', 'risk_acceptance')),
  outcome text NOT NULL,
  rationale text NOT NULL CHECK (length(rationale) BETWEEN 1 AND 10000),
  limitations text,
  actor_principal_id uuid NOT NULL,
  authority jsonb NOT NULL,          -- role bindings / limits relied on, evaluated at decision time
  policy_version_id uuid,            -- Phase C: references policy_versions
  evidence_snapshot_id uuid,         -- Phase C: references evidence_snapshots
  supersedes_decision_id uuid,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, supersedes_decision_id) REFERENCES axiom.decisions(tenant_id, id),
  CHECK (kind <> 'assessment' OR outcome IN ('supported', 'not_supported', 'inconclusive'))
);
CREATE INDEX decisions_case ON axiom.decisions(tenant_id, case_id, recorded_at);
CREATE TRIGGER decisions_append_only BEFORE UPDATE OR DELETE ON axiom.decisions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.decision_evidence (
  tenant_id uuid NOT NULL,
  decision_id uuid NOT NULL,
  evidence_object_id uuid NOT NULL,
  relation text NOT NULL CHECK (relation IN ('supports', 'contradicts', 'context')),
  PRIMARY KEY (tenant_id, decision_id, evidence_object_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_object_id) REFERENCES axiom.evidence_objects(tenant_id, id)
);
CREATE FUNCTION axiom.decision_evidence_verified() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM axiom.evidence_objects e WHERE e.tenant_id = NEW.tenant_id
                 AND e.id = NEW.evidence_object_id AND e.status = 'verified') THEN
    RAISE EXCEPTION 'only verified evidence may support a decision' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER decision_evidence_verified BEFORE INSERT ON axiom.decision_evidence
  FOR EACH ROW EXECUTE FUNCTION axiom.decision_evidence_verified();
CREATE TRIGGER decision_evidence_append_only BEFORE UPDATE OR DELETE ON axiom.decision_evidence
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Transition history; every case write has exactly one event at its new version.
CREATE TABLE axiom.case_events (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  event_type text NOT NULL,
  from_workflow text,
  to_workflow text NOT NULL,
  actor_principal_id uuid NOT NULL,
  decision_id uuid,
  audit_event_id uuid NOT NULL,
  correlation_id text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, case_id, sequence),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  FOREIGN KEY (tenant_id, audit_event_id) REFERENCES axiom.audit_events(tenant_id, id)
);
CREATE TRIGGER case_events_append_only BEFORE UPDATE OR DELETE ON axiom.case_events
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Reported change with the affected deployment identified.
CREATE TABLE axiom.remediation_reports (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  target_asset_version_id uuid NOT NULL,
  change_reference text NOT NULL,
  evidence_object_id uuid,
  reported_by uuid NOT NULL,
  decision_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, target_asset_version_id) REFERENCES axiom.asset_versions(tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_object_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id)
);
CREATE TRIGGER remediation_reports_append_only BEFORE UPDATE OR DELETE ON axiom.remediation_reports
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- The target deployment must be a version of an asset affected by the case.
CREATE FUNCTION axiom.remediation_report_target() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM axiom.asset_versions target
      JOIN axiom.asset_versions affected ON affected.tenant_id = target.tenant_id
                                     AND affected.asset_id = target.asset_id
      JOIN axiom.finding_occurrences o ON o.tenant_id = affected.tenant_id AND o.asset_version_id = affected.id
      JOIN axiom.case_occurrence_links l ON l.tenant_id = o.tenant_id AND l.occurrence_id = o.id
     WHERE target.tenant_id = NEW.tenant_id AND target.id = NEW.target_asset_version_id
       AND l.case_id = NEW.case_id AND l.unlinked_at IS NULL) THEN
    RAISE EXCEPTION 'remediation target is not a deployment of an asset affected by this case'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER remediation_report_target BEFORE INSERT ON axiom.remediation_reports
  FOR EACH ROW EXECUTE FUNCTION axiom.remediation_report_target();

CREATE TABLE axiom.verification_runs (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  remediation_report_id uuid NOT NULL,
  observed_asset_version_id uuid,
  criteria jsonb NOT NULL,
  criteria_digest text NOT NULL CHECK (criteria_digest ~ '^[0-9a-f]{64}$'),
  coverage text NOT NULL CHECK (coverage IN ('complete', 'partial', 'none')),
  outcome text NOT NULL CHECK (outcome IN ('passed', 'failed', 'inconclusive')),
  outcome_reason text NOT NULL,
  evidence_object_id uuid,
  recorded_by uuid NOT NULL,
  decision_id uuid NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, remediation_report_id) REFERENCES axiom.remediation_reports(tenant_id, id),
  FOREIGN KEY (tenant_id, observed_asset_version_id) REFERENCES axiom.asset_versions(tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_object_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  -- Incomplete coverage or unknown deployment can never pass.
  CHECK (outcome <> 'passed' OR (coverage = 'complete' AND observed_asset_version_id IS NOT NULL
                                 AND evidence_object_id IS NOT NULL))
);
CREATE TRIGGER verification_runs_append_only BEFORE UPDATE OR DELETE ON axiom.verification_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE FUNCTION axiom.verification_run_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  r record;
BEGIN
  SELECT * INTO r FROM axiom.remediation_reports
   WHERE tenant_id = NEW.tenant_id AND id = NEW.remediation_report_id;
  IF r.case_id <> NEW.case_id THEN
    RAISE EXCEPTION 'verification refers to another case''s remediation report' USING ERRCODE = '23514';
  END IF;
  IF NEW.outcome = 'passed' THEN
    IF NEW.observed_asset_version_id IS DISTINCT FROM r.target_asset_version_id THEN
      RAISE EXCEPTION 'passed verification must observe the reported deployment' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM axiom.evidence_objects e WHERE e.tenant_id = NEW.tenant_id
                   AND e.id = NEW.evidence_object_id AND e.status = 'verified') THEN
      RAISE EXCEPTION 'passed verification requires verified evidence' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER verification_run_guard BEFORE INSERT ON axiom.verification_runs
  FOR EACH ROW EXECUTE FUNCTION axiom.verification_run_guard();

CREATE TABLE axiom.risk_acceptances (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  owner_principal_id uuid NOT NULL,
  decision_id uuid NOT NULL,
  delegation_limit_id uuid NOT NULL,
  rationale text NOT NULL,
  compensating_controls text,
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
  ended_at timestamptz,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  FOREIGN KEY (tenant_id, delegation_limit_id) REFERENCES axiom.delegation_limits(tenant_id, id),
  CHECK (expires_at > starts_at),
  CHECK ((status = 'active') = (ended_at IS NULL))
);
CREATE INDEX risk_acceptances_expiry ON axiom.risk_acceptances(expires_at) WHERE status = 'active';
CREATE FUNCTION axiom.risk_acceptance_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.owner_principal_id, NEW.decision_id, NEW.delegation_limit_id,
      NEW.rationale, NEW.compensating_controls, NEW.starts_at, NEW.expires_at, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.case_id, OLD.owner_principal_id, OLD.decision_id, OLD.delegation_limit_id,
      OLD.rationale, OLD.compensating_controls, OLD.starts_at, OLD.expires_at, OLD.created_at) THEN
    RAISE EXCEPTION 'risk acceptance terms are immutable; record a new acceptance' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'active' THEN
    RAISE EXCEPTION 'ended risk acceptance cannot change' USING ERRCODE = '42501';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'risk acceptance record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER risk_acceptance_guard BEFORE UPDATE ON axiom.risk_acceptances
  FOR EACH ROW EXECUTE FUNCTION axiom.risk_acceptance_guard();
CREATE TRIGGER risk_acceptance_no_delete BEFORE DELETE ON axiom.risk_acceptances
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.closure_records (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  case_event_sequence bigint NOT NULL,
  reason text NOT NULL CHECK (reason IN ('verified_remediated', 'accepted_risk', 'dismissed', 'duplicate', 'asset_retired')),
  decision_id uuid NOT NULL,
  verification_run_id uuid,
  risk_acceptance_id uuid,
  duplicate_of_case_id uuid,
  retirement_evidence_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, case_id, case_event_sequence),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  FOREIGN KEY (tenant_id, verification_run_id) REFERENCES axiom.verification_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, risk_acceptance_id) REFERENCES axiom.risk_acceptances(tenant_id, id),
  FOREIGN KEY (tenant_id, duplicate_of_case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, retirement_evidence_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  CHECK ((reason = 'verified_remediated') = (verification_run_id IS NOT NULL)),
  CHECK ((reason = 'accepted_risk') = (risk_acceptance_id IS NOT NULL)),
  CHECK ((reason = 'duplicate') = (duplicate_of_case_id IS NOT NULL)),
  CHECK ((reason = 'asset_retired') = (retirement_evidence_id IS NOT NULL)),
  CHECK (duplicate_of_case_id IS DISTINCT FROM case_id)
);
CREATE TRIGGER closure_records_append_only BEFORE UPDATE OR DELETE ON axiom.closure_records
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------
-- Case guards
-- ---------------------------------------------------------------------------
CREATE FUNCTION axiom.case_transition_allowed(p_from text, p_to text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT (p_from, p_to) IN (
    ('received', 'investigating'),
    ('investigating', 'review_required'),
    ('review_required', 'investigating'),
    ('review_required', 'remediation_planned'),
    ('remediation_planned', 'remediating'),
    ('remediating', 'awaiting_verification'),
    ('awaiting_verification', 'closed'),
    ('awaiting_verification', 'remediating'),
    ('awaiting_verification', 'review_required'),
    ('review_required', 'closed'),
    ('closed', 'investigating'))
$$;

CREATE FUNCTION axiom.finding_cases_row_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.workflow <> 'received' OR NEW.assessment <> 'unassessed' OR NEW.priority <> 'pending'
       OR NEW.disposition <> 'unset' OR NEW.record_version <> 0 THEN
      RAISE EXCEPTION 'cases are created as received/unassessed/pending/unset at version 0'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'case identity and scope are immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'stale or skipped case version' USING ERRCODE = '40001';
  END IF;
  IF NEW.workflow <> OLD.workflow AND NOT axiom.case_transition_allowed(OLD.workflow, NEW.workflow) THEN
    RAISE EXCEPTION 'case transition % -> % is not allowed', OLD.workflow, NEW.workflow USING ERRCODE = '23514';
  END IF;
  IF OLD.workflow = 'closed' AND NEW.workflow = 'closed' THEN
    RAISE EXCEPTION 'closed case is immutable until reopened' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER finding_cases_row_guard BEFORE INSERT OR UPDATE ON axiom.finding_cases
  FOR EACH ROW EXECUTE FUNCTION axiom.finding_cases_row_guard();
CREATE TRIGGER finding_cases_no_delete BEFORE DELETE ON axiom.finding_cases
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Reason-specific closure prerequisites, evaluated at commit.
CREATE FUNCTION axiom.validate_closure(p_tenant uuid, p_case uuid, p_sequence bigint, p_from text) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  c record; cs record; vr record; ra record; latest_report uuid; a record;
BEGIN
  SELECT * INTO c FROM axiom.closure_records
   WHERE tenant_id = p_tenant AND case_id = p_case AND case_event_sequence = p_sequence;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'closure requires a closure record' USING ERRCODE = '23514';
  END IF;
  SELECT * INTO cs FROM axiom.finding_cases WHERE tenant_id = p_tenant AND id = p_case;

  IF c.reason = 'verified_remediated' THEN
    IF p_from <> 'awaiting_verification' THEN
      RAISE EXCEPTION 'verified closure requires the verification workflow' USING ERRCODE = '23514';
    END IF;
    IF cs.assessment <> 'supported' THEN
      RAISE EXCEPTION 'case with % assessment cannot close as verified remediated', cs.assessment
        USING ERRCODE = '23514';
    END IF;
    SELECT * INTO vr FROM axiom.verification_runs WHERE tenant_id = p_tenant AND id = c.verification_run_id;
    SELECT id INTO latest_report FROM axiom.remediation_reports
     WHERE tenant_id = p_tenant AND case_id = p_case ORDER BY created_at DESC, id DESC LIMIT 1;
    IF vr.case_id <> p_case OR vr.outcome <> 'passed' OR vr.coverage <> 'complete'
       OR vr.remediation_report_id <> latest_report THEN
      RAISE EXCEPTION 'verified closure requires a passed, complete verification of the latest reported change'
        USING ERRCODE = '23514';
    END IF;
    RETURN;
  END IF;

  IF p_from <> 'review_required' THEN
    RAISE EXCEPTION '% closure requires review', c.reason USING ERRCODE = '23514';
  END IF;

  IF c.reason = 'accepted_risk' THEN
    SELECT * INTO ra FROM axiom.risk_acceptances WHERE tenant_id = p_tenant AND id = c.risk_acceptance_id;
    IF ra.case_id <> p_case OR ra.status <> 'active' OR ra.starts_at > clock_timestamp()
       OR ra.expires_at <= clock_timestamp() THEN
      RAISE EXCEPTION 'risk acceptance is not active for this case' USING ERRCODE = '23514';
    END IF;
  ELSIF c.reason = 'dismissed' THEN
    IF cs.assessment <> 'not_supported' THEN
      RAISE EXCEPTION 'dismissal requires a not_supported assessment' USING ERRCODE = '23514';
    END IF;
    SELECT d.* INTO a FROM axiom.decisions d
     WHERE d.tenant_id = p_tenant AND d.case_id = p_case AND d.kind = 'assessment'
     ORDER BY d.recorded_at DESC, d.id DESC LIMIT 1;
    IF a.outcome IS DISTINCT FROM 'not_supported' OR NOT EXISTS (
        SELECT 1 FROM axiom.decision_evidence de WHERE de.tenant_id = p_tenant
           AND de.decision_id = a.id AND de.relation = 'supports') THEN
      RAISE EXCEPTION 'dismissal requires an evidence-backed not_supported assessment' USING ERRCODE = '23514';
    END IF;
    IF a.actor_principal_id = (SELECT actor_principal_id FROM axiom.decisions
                                WHERE tenant_id = p_tenant AND id = c.decision_id) THEN
      RAISE EXCEPTION 'dismissal cannot be approved by the assessor' USING ERRCODE = '23514';
    END IF;
  ELSIF c.reason = 'asset_retired' THEN
    IF NOT EXISTS (SELECT 1 FROM axiom.evidence_objects e WHERE e.tenant_id = p_tenant
                   AND e.id = c.retirement_evidence_id AND e.status = 'verified') THEN
      RAISE EXCEPTION 'asset retirement requires verified lifecycle evidence' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
         SELECT 1 FROM axiom.case_occurrence_links l
           JOIN axiom.finding_occurrences o ON o.tenant_id = l.tenant_id AND o.id = l.occurrence_id
          WHERE l.tenant_id = p_tenant AND l.case_id = p_case AND l.unlinked_at IS NULL)
       OR EXISTS (
         SELECT 1 FROM axiom.case_occurrence_links l
           JOIN axiom.finding_occurrences o ON o.tenant_id = l.tenant_id AND o.id = l.occurrence_id
           JOIN axiom.asset_versions v ON v.tenant_id = o.tenant_id AND v.id = o.asset_version_id
           JOIN axiom.assets s ON s.tenant_id = v.tenant_id AND s.id = v.asset_id
          WHERE l.tenant_id = p_tenant AND l.case_id = p_case AND l.unlinked_at IS NULL
            AND s.lifecycle_status <> 'retired') THEN
      RAISE EXCEPTION 'every affected asset must be retired' USING ERRCODE = '23514';
    END IF;
  END IF;
  -- 'duplicate': the composite FK and CHECK already require a distinct case in the same tenant.
END
$$;

CREATE FUNCTION axiom.finding_cases_commit_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  ev record;
  from_state text := CASE WHEN TG_OP = 'UPDATE' THEN OLD.workflow END;
BEGIN
  SELECT e.* INTO ev FROM axiom.case_events e
   WHERE e.tenant_id = NEW.tenant_id AND e.case_id = NEW.id AND e.sequence = NEW.record_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'case write at version % has no case event', NEW.record_version USING ERRCODE = '23514';
  END IF;
  IF ev.to_workflow <> NEW.workflow OR ev.from_workflow IS DISTINCT FROM from_state THEN
    RAISE EXCEPTION 'case event does not describe the committed transition' USING ERRCODE = '23514';
  END IF;
  IF NEW.workflow = 'closed' AND from_state IS DISTINCT FROM 'closed' THEN
    PERFORM axiom.validate_closure(NEW.tenant_id, NEW.id, NEW.record_version, from_state);
  END IF;
  RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER finding_cases_commit_guard AFTER INSERT OR UPDATE ON axiom.finding_cases
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION axiom.finding_cases_commit_guard();

-- ---------------------------------------------------------------------------
-- Row-level security and grants
-- ---------------------------------------------------------------------------
SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY[
  'assets', 'asset_versions', 'finding_occurrences', 'finding_cases', 'case_occurrence_links',
  'decisions', 'decision_evidence', 'case_events', 'remediation_reports', 'verification_runs',
  'risk_acceptances', 'closure_records']) AS t;

GRANT SELECT, INSERT ON axiom.assets, axiom.asset_versions, axiom.finding_occurrences, axiom.finding_cases,
  axiom.case_occurrence_links, axiom.decisions, axiom.decision_evidence, axiom.case_events, axiom.remediation_reports,
  axiom.verification_runs, axiom.risk_acceptances, axiom.closure_records TO axiom_runtime;
GRANT UPDATE (workflow, assessment, priority, disposition, owner_principal_id, review_at,
  record_version, updated_at) ON axiom.finding_cases TO axiom_runtime;
GRANT UPDATE (lifecycle_status, retirement_evidence_id, record_version) ON axiom.assets TO axiom_runtime;
GRANT UPDATE (status, ended_at, record_version) ON axiom.risk_acceptances TO axiom_runtime;
GRANT UPDATE (unlinked_at, unlinked_by) ON axiom.case_occurrence_links TO axiom_runtime;
