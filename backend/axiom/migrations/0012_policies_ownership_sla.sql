-- 0012 Versioned policies (priority, ownership, SLA, freshness), prioritisation and ownership commands, SLA timers v2.

-- ---------------------------------------------------------------------------- policy versions
-- A policy is drafted, then published by a different principal (independent approval, Specification S 8 / Design
-- S 12). Definitions are immutable and digested by the database; publishing supersedes the previous version.
CREATE TABLE axiom.policy_versions (
  tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('priority', 'ownership', 'sla', 'freshness')),
  version int NOT NULL CHECK (version >= 1),
  status text NOT NULL CHECK (status IN ('draft', 'published', 'superseded', 'withdrawn')),
  definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
  definition_digest text NOT NULL,
  provisional boolean NOT NULL,          -- thresholds not yet confirmed by the business (Specification S 17)
  rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
  drafted_by uuid NOT NULL,
  published_by uuid,
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, kind, version),
  CHECK ((status IN ('published', 'superseded')) = (published_at IS NOT NULL)),
  CHECK (published_by IS NULL OR published_by <> drafted_by)
);
CREATE UNIQUE INDEX policy_versions_one_published ON axiom.policy_versions(tenant_id, kind) WHERE status = 'published';

CREATE FUNCTION axiom.policy_versions_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'draft' OR NEW.published_by IS NOT NULL THEN
      RAISE EXCEPTION 'policies are created as drafts' USING ERRCODE = '23514';
    END IF;
    NEW.definition_digest := encode(sha256(convert_to(NEW.definition::text, 'UTF8')), 'hex');
    RETURN NEW;
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.kind, NEW.version, NEW.definition, NEW.definition_digest, NEW.provisional,
      NEW.rationale, NEW.drafted_by, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.kind, OLD.version, OLD.definition, OLD.definition_digest,
                       OLD.provisional, OLD.rationale, OLD.drafted_by, OLD.created_at) THEN
    RAISE EXCEPTION 'policy definitions are immutable; draft a new version' USING ERRCODE = '42501';
  END IF;
  IF NOT ((OLD.status, NEW.status) IN (('draft', 'published'), ('draft', 'withdrawn'), ('published', 'superseded'))) THEN
    RAISE EXCEPTION 'policy % -> % not permitted', OLD.status, NEW.status USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'policy record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER policy_versions_guard BEFORE INSERT OR UPDATE ON axiom.policy_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.policy_versions_guard();
CREATE TRIGGER policy_versions_no_delete BEFORE DELETE ON axiom.policy_versions
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

ALTER TABLE axiom.decisions ADD CONSTRAINT decisions_policy_version
  FOREIGN KEY (tenant_id, policy_version_id) REFERENCES axiom.policy_versions(tenant_id, id);
ALTER TABLE axiom.decisions DROP CONSTRAINT decisions_kind_check;
ALTER TABLE axiom.decisions ADD CONSTRAINT decisions_kind_check CHECK (kind IN ('investigation_start', 'assessment',
  'escalation', 'evidence_request', 'remediation_plan', 'external_work', 'remediation_report', 'verification_review',
  'deferral', 'closure', 'reopen', 'owner_assignment', 'risk_acceptance', 'remediation_withdrawal', 'prioritisation',
  'priority_override'));

-- ---------------------------------------------------------------------------- ownership
-- Append-only routing history; the latest row is the current accountable owner. Ownership confers no authority.
CREATE TABLE axiom.case_ownership (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  owner_principal_id uuid,
  basis text NOT NULL CHECK (basis IN ('rule', 'manual_override', 'unresolved')),
  policy_version_id uuid,
  rule_id text,
  reason text NOT NULL,
  context jsonb NOT NULL,                -- the explicit inputs the decision used
  assigned_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, policy_version_id) REFERENCES axiom.policy_versions(tenant_id, id),
  CHECK ((basis = 'unresolved') = (owner_principal_id IS NULL)),
  CHECK ((basis = 'rule') = (rule_id IS NOT NULL)),
  CHECK (basis <> 'rule' OR policy_version_id IS NOT NULL)
);
CREATE INDEX case_ownership_current ON axiom.case_ownership(tenant_id, case_id, created_at DESC);
CREATE TRIGGER case_ownership_append_only BEFORE UPDATE OR DELETE ON axiom.case_ownership
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- SLA timers v2
-- Replaces 0011's case_slas (no production data existed): triage and remediation timers are separate, pauses are
-- derived from case events, and priority changes revise the due date from the original start (no reset).
DROP TABLE axiom.case_slas;
DROP FUNCTION axiom.case_slas_guard();

CREATE TABLE axiom.sla_timers (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('triage', 'remediation')),
  cycle int NOT NULL CHECK (cycle >= 1),               -- increments when a closed case is reopened
  priority text NOT NULL,
  policy_version_id uuid,                               -- NULL when the built-in provisional default applied
  policy_snapshot jsonb NOT NULL,
  started_at timestamptz NOT NULL,
  paused_seconds bigint NOT NULL DEFAULT 0 CHECK (paused_seconds >= 0),
  paused_since timestamptz,
  due_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('running', 'paused', 'breached', 'met', 'missed', 'risk_accepted',
                                         'closed_without_fix', 'revised')),
  breached_at timestamptz,
  ended_at timestamptz,
  end_reason text,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_version_id) REFERENCES axiom.policy_versions(tenant_id, id),
  CHECK ((status IN ('running', 'paused', 'breached')) = (ended_at IS NULL)),
  CHECK ((status = 'paused') = (paused_since IS NOT NULL))
);
CREATE UNIQUE INDEX sla_timers_one_active ON axiom.sla_timers(tenant_id, case_id, kind)
  WHERE status IN ('running', 'paused', 'breached');

CREATE FUNCTION axiom.sla_timers_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.kind, NEW.cycle, NEW.priority, NEW.policy_version_id,
      NEW.policy_snapshot, NEW.started_at, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.case_id, OLD.kind, OLD.cycle, OLD.priority, OLD.policy_version_id,
                       OLD.policy_snapshot, OLD.started_at, OLD.created_at) THEN
    RAISE EXCEPTION 'SLA timer terms are immutable; a priority change revises into a new timer' USING ERRCODE = '42501';
  END IF;
  IF OLD.status NOT IN ('running', 'paused', 'breached') THEN
    RAISE EXCEPTION 'ended SLA timer is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.paused_seconds < OLD.paused_seconds THEN
    RAISE EXCEPTION 'paused time cannot decrease' USING ERRCODE = '23514';
  END IF;
  IF OLD.breached_at IS NOT NULL AND NEW.breached_at IS DISTINCT FROM OLD.breached_at THEN
    RAISE EXCEPTION 'a recorded breach cannot be undone' USING ERRCODE = '23514';
  END IF;
  IF NEW.status = 'met' AND OLD.breached_at IS NOT NULL THEN
    RAISE EXCEPTION 'a breached timer cannot be met' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'SLA record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER sla_timers_guard BEFORE UPDATE ON axiom.sla_timers FOR EACH ROW EXECUTE FUNCTION axiom.sla_timers_guard();
CREATE TRIGGER sla_timers_no_delete BEFORE DELETE ON axiom.sla_timers FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Auditor evidence packages are stored as snapshots of their own kind.
ALTER TABLE axiom.report_snapshots DROP CONSTRAINT report_snapshots_kind_check;
ALTER TABLE axiom.report_snapshots ADD CONSTRAINT report_snapshots_kind_check
  CHECK (kind IN ('exposure_summary', 'evidence_package'));

-- ---------------------------------------------------------------------------- permissions, RLS, grants
INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('priority.apply', false, 'Apply the published priority policy to a case'),
 ('ownership.route', false, 'Route a case to an owner by the published ownership policy'),
 ('ownership.override', false, 'Manually assign or reassign a case owner with a reason'),
 ('context.assert', false, 'Assert business context (owner reference, criticality, environment) for an asset');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'priority.apply'), ('analyst', 'override.propose'), ('analyst', 'ownership.route'),
 ('analyst', 'ownership.override'), ('analyst', 'context.assert'), ('ingestion_worker', 'priority.apply'),
 ('ingestion_worker', 'ownership.route'), ('policy_admin', 'case.read'), ('policy_admin', 'proposal.read')
ON CONFLICT DO NOTHING;

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY['policy_versions', 'case_ownership', 'sla_timers']) AS t;
GRANT SELECT, INSERT ON axiom.policy_versions, axiom.case_ownership, axiom.sla_timers TO axiom_runtime;
GRANT UPDATE (status, published_by, published_at, record_version) ON axiom.policy_versions TO axiom_runtime;
GRANT UPDATE (paused_seconds, paused_since, due_at, status, breached_at, ended_at, end_reason, record_version)
  ON axiom.sla_timers TO axiom_runtime;
