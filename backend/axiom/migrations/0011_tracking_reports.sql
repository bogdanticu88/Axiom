-- 0011 Phase D tracking: inbound ticket state, SLA timers, immutable report snapshots and exports.

-- ---------------------------------------------------------------------------- inbound ticket state (ACT-09)
-- Append-only observations of an external ticket's state, recorded when it changes. Observations never move the
-- platform case: an externally closed ticket does not close the case.
CREATE TABLE axiom.external_ticket_states (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  reference_id uuid NOT NULL,
  status text NOT NULL,
  status_category text NOT NULL CHECK (status_category IN ('open', 'in_progress', 'done', 'missing', 'unknown')),
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  source text NOT NULL CHECK (source IN ('poll', 'webhook')),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, reference_id) REFERENCES axiom.external_references(tenant_id, id)
);
CREATE INDEX external_ticket_states_ref ON axiom.external_ticket_states(tenant_id, reference_id, observed_at DESC);
CREATE TRIGGER external_ticket_states_append_only BEFORE UPDATE OR DELETE ON axiom.external_ticket_states
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- SLA timers
CREATE TABLE axiom.case_slas (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  priority text NOT NULL,
  policy jsonb NOT NULL,                 -- the thresholds in force when the timer started (defaults D-SLA-1)
  started_at timestamptz NOT NULL,
  due_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('running', 'breached', 'met', 'missed', 'superseded')),
  breached_at timestamptz,
  ended_at timestamptz,
  end_reason text,
  record_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  CHECK (due_at > started_at),
  CHECK ((status IN ('running', 'breached')) = (ended_at IS NULL)),
  CHECK ((status IN ('breached', 'missed')) = (breached_at IS NOT NULL))
);
CREATE UNIQUE INDEX case_slas_one_active ON axiom.case_slas(tenant_id, case_id) WHERE status IN ('running', 'breached');

CREATE FUNCTION axiom.case_slas_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.priority, NEW.policy, NEW.started_at, NEW.due_at, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.case_id, OLD.priority, OLD.policy, OLD.started_at, OLD.due_at,
                       OLD.created_at) THEN
    RAISE EXCEPTION 'SLA timer terms are immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status IN ('met', 'missed', 'superseded') THEN
    RAISE EXCEPTION 'ended SLA timer is immutable' USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'breached' AND NEW.status IN ('running', 'met') THEN
    RAISE EXCEPTION 'a breached SLA cannot become running or met' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'SLA record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER case_slas_guard BEFORE UPDATE ON axiom.case_slas FOR EACH ROW EXECUTE FUNCTION axiom.case_slas_guard();
CREATE TRIGGER case_slas_no_delete BEFORE DELETE ON axiom.case_slas FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- ---------------------------------------------------------------------------- report snapshots and exports
CREATE TABLE axiom.report_snapshots (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('exposure_summary')),
  scope_id uuid NOT NULL,
  parameters jsonb NOT NULL,
  content jsonb NOT NULL,
  content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
  generated_by uuid NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id)
);
CREATE TRIGGER report_snapshots_immutable BEFORE UPDATE OR DELETE ON axiom.report_snapshots
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE TABLE axiom.report_exports (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  format text NOT NULL CHECK (format IN ('json', 'csv')),
  object_key text NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES axiom.report_snapshots(tenant_id, id)
);
CREATE TRIGGER report_exports_immutable BEFORE UPDATE OR DELETE ON axiom.report_exports
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('report.generate', false, 'Generate an immutable report snapshot for a scope'),
 ('report.export', true, 'Export a report snapshot as a file');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'report.generate'), ('auditor', 'report.generate'), ('auditor', 'report.export');

SELECT axiom.apply_tenant_policy(t) FROM unnest(ARRAY['external_ticket_states', 'case_slas', 'report_snapshots',
  'report_exports']) AS t;
GRANT SELECT, INSERT ON axiom.external_ticket_states, axiom.case_slas, axiom.report_snapshots, axiom.report_exports TO axiom_runtime;
GRANT UPDATE (status, breached_at, ended_at, end_reason, record_version) ON axiom.case_slas TO axiom_runtime;
