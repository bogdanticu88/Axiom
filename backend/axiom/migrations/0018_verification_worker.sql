-- 0018 Verification worker (ADR 0014).
--
-- * A distinct workload identity per tenant for automated verification checks, recorded on the tenant
--   (axiom.tenants.verification_principal_id) by the provisioning identity. Its authority is an ordinary, revocable role
--   binding to the workload role verification_worker, which holds only what recording a check needs:
--     verification.record          record the verification observation (decision kind verification_review)
--     evidence.upload              preserve the check endpoint's response as evidence
--     evidence.read:confidential   cite that evidence (citing requires read permission at its classification)
--   It holds no case.reopen, closure, approval, assessment or risk permission. The decision guard (0017) already
--   allows a workload verification_review only with verification.record at the case scope.
-- * axiom.verification_observations: provenance of each automated check (source, request and response times, response
--   digest, the rule that decided the outcome, the job and lease that recorded it). Append-only, one row per job,
--   recorded only by the principal bound to the transaction, and only for a verification run that principal recorded
--   for the same case and report in the same transaction.

INSERT INTO axiom.roles(id, description, principal_kind) VALUES
 ('verification_worker', 'Workload role for the tenant verification identity that records automated checks', 'workload');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('verification_worker', 'verification.record'), ('verification_worker', 'evidence.upload'),
 ('verification_worker', 'evidence.read:confidential');

ALTER TABLE axiom.tenants ADD COLUMN verification_principal_id uuid REFERENCES axiom.principals(id);
GRANT UPDATE (verification_principal_id) ON axiom.tenants TO axiom_provisioner;

CREATE TABLE axiom.verification_observations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  remediation_report_id uuid NOT NULL,
  verification_run_id uuid NOT NULL,
  job_id uuid NOT NULL,
  lease_token bigint NOT NULL,
  worker text NOT NULL CHECK (length(worker) BETWEEN 1 AND 200),
  connection_id uuid NOT NULL,
  source_adapter text NOT NULL CHECK (source_adapter ~ '^[a-z0-9_]+$'),
  source_origin text NOT NULL CHECK (source_origin ~ '^https?://[^/?#@]+$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  requested_at timestamptz NOT NULL,
  received_at timestamptz,
  http_status int,
  response_digest text CHECK (response_digest IS NULL OR response_digest ~ '^[0-9a-f]{64}$'),
  evidence_object_id uuid,
  target_observed_at timestamptz,
  observed_deployment_digest text,
  rule text NOT NULL CHECK (rule ~ '^[a-z_]+$'),
  attempts int NOT NULL CHECK (attempts >= 1),
  recorded_by uuid NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, job_id),
  UNIQUE (tenant_id, verification_run_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, remediation_report_id) REFERENCES axiom.remediation_reports(tenant_id, id),
  FOREIGN KEY (tenant_id, verification_run_id) REFERENCES axiom.verification_runs(tenant_id, id),
  FOREIGN KEY (tenant_id, job_id) REFERENCES axiom.jobs(tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES axiom.connections(tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_object_id) REFERENCES axiom.evidence_objects(tenant_id, id),
  CHECK ((response_digest IS NULL) = (received_at IS NULL))
);
CREATE TRIGGER verification_observations_append_only BEFORE UPDATE OR DELETE ON axiom.verification_observations
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

CREATE FUNCTION axiom.verification_observation_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  run record;
BEGIN
  IF NEW.recorded_by IS DISTINCT FROM axiom.current_principal() THEN
    RAISE EXCEPTION 'verification observations must be recorded by the principal bound to the transaction'
      USING ERRCODE = '42501';
  END IF;
  SELECT r.case_id, r.remediation_report_id, r.recorded_by, r.evidence_object_id,
         r.xmin = pg_current_xact_id()::xid AS this_tx
    INTO run FROM axiom.verification_runs r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.verification_run_id;
  IF NOT FOUND OR run.recorded_by <> NEW.recorded_by OR run.case_id <> NEW.case_id
     OR run.remediation_report_id <> NEW.remediation_report_id OR NOT run.this_tx
     OR run.evidence_object_id IS DISTINCT FROM NEW.evidence_object_id AND run.evidence_object_id IS NOT NULL THEN
    RAISE EXCEPTION 'an observation must describe a verification run its recorder made in the same transaction'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER verification_observation_guard BEFORE INSERT ON axiom.verification_observations
  FOR EACH ROW EXECUTE FUNCTION axiom.verification_observation_guard();

SELECT axiom.apply_tenant_policy('verification_observations');
GRANT SELECT, INSERT ON axiom.verification_observations TO axiom_runtime;
