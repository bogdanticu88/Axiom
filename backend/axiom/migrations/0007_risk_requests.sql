-- 0007 Two-step risk acceptance (RISK-02; review finding R9): request, authorise or reject, renew, reassess.
--
-- A request records what is asked (case state at the time, priority, requested expiry, rationale, controls) and the
-- policy evaluation (whether independent authorisation is required). Authorisation creates the acceptance and closes
-- the case through the existing closure route; a renewal creates a new acceptance that supersedes the old one.

CREATE TABLE axiom.risk_acceptance_requests (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  scope_id uuid NOT NULL,
  requested_by uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('new', 'renewal')),
  renewal_of uuid,
  case_record_version bigint NOT NULL,
  case_priority text NOT NULL,
  rationale text NOT NULL CHECK (length(btrim(rationale)) > 0),
  compensating_controls text,
  requested_expires_at timestamptz NOT NULL,
  independent_required boolean NOT NULL,
  policy jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'authorised', 'rejected', 'withdrawn', 'lapsed')),
  lapses_at timestamptz NOT NULL,
  decided_by uuid,
  decided_at timestamptz,
  decision_rationale text,
  acceptance_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, scope_id) REFERENCES axiom.scopes(tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES axiom.memberships(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, renewal_of) REFERENCES axiom.risk_acceptances(tenant_id, id),
  FOREIGN KEY (tenant_id, acceptance_id) REFERENCES axiom.risk_acceptances(tenant_id, id),
  CHECK ((kind = 'renewal') = (renewal_of IS NOT NULL)),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK ((status = 'authorised') = (acceptance_id IS NOT NULL)),
  CHECK (status NOT IN ('authorised', 'rejected') OR decided_by IS NOT NULL),
  -- independence: when policy requires it, the requester cannot authorise (database backstop for the service)
  CHECK (NOT (independent_required AND status = 'authorised' AND decided_by = requested_by))
);
CREATE UNIQUE INDEX risk_requests_one_pending_per_case
  ON axiom.risk_acceptance_requests(tenant_id, case_id) WHERE status = 'pending';

CREATE FUNCTION axiom.risk_requests_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.scope_id, NEW.requested_by, NEW.kind, NEW.renewal_of,
      NEW.case_record_version, NEW.case_priority, NEW.rationale, NEW.compensating_controls,
      NEW.requested_expires_at, NEW.independent_required, NEW.policy, NEW.lapses_at, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.case_id, OLD.scope_id, OLD.requested_by, OLD.kind, OLD.renewal_of,
      OLD.case_record_version, OLD.case_priority, OLD.rationale, OLD.compensating_controls,
      OLD.requested_expires_at, OLD.independent_required, OLD.policy, OLD.lapses_at, OLD.created_at) THEN
    RAISE EXCEPTION 'risk acceptance request terms are immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'decided risk acceptance request is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'request record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER risk_requests_guard BEFORE UPDATE ON axiom.risk_acceptance_requests
  FOR EACH ROW EXECUTE FUNCTION axiom.risk_requests_guard();
CREATE TRIGGER risk_requests_no_delete BEFORE DELETE ON axiom.risk_acceptance_requests
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

-- Link acceptances to their request and renewal chain; reassessment notices are recorded once per acceptance.
ALTER TABLE axiom.risk_acceptances
  ADD COLUMN request_id uuid,
  ADD COLUMN renewal_of uuid,
  ADD COLUMN reassessment_notified_at timestamptz,
  ADD FOREIGN KEY (tenant_id, request_id) REFERENCES axiom.risk_acceptance_requests(tenant_id, id),
  ADD FOREIGN KEY (tenant_id, renewal_of) REFERENCES axiom.risk_acceptances(tenant_id, id);
CREATE UNIQUE INDEX risk_acceptances_one_renewal ON axiom.risk_acceptances(tenant_id, renewal_of)
  WHERE renewal_of IS NOT NULL;

-- request_id and renewal_of are set at insert only; extend the existing immutability guard to cover them.
CREATE OR REPLACE FUNCTION axiom.risk_acceptance_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.owner_principal_id, NEW.decision_id, NEW.delegation_limit_id,
      NEW.rationale, NEW.compensating_controls, NEW.starts_at, NEW.expires_at, NEW.created_at, NEW.request_id,
      NEW.renewal_of)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.case_id, OLD.owner_principal_id, OLD.decision_id, OLD.delegation_limit_id,
      OLD.rationale, OLD.compensating_controls, OLD.starts_at, OLD.expires_at, OLD.created_at, OLD.request_id,
      OLD.renewal_of) THEN
    RAISE EXCEPTION 'risk acceptance terms are immutable; record a new acceptance' USING ERRCODE = '42501';
  END IF;
  IF OLD.status <> 'active' THEN
    RAISE EXCEPTION 'ended risk acceptance cannot change' USING ERRCODE = '42501';
  END IF;
  IF OLD.reassessment_notified_at IS NOT NULL
     AND NEW.reassessment_notified_at IS DISTINCT FROM OLD.reassessment_notified_at THEN
    RAISE EXCEPTION 'reassessment notice is recorded once' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'risk acceptance record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;

INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('risk.request', false, 'Request risk acceptance or renewal for a case in scope');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'risk.request'), ('remediation_owner', 'risk.request'), ('risk_owner', 'risk.request');

SELECT axiom.apply_tenant_policy('risk_acceptance_requests');
GRANT SELECT, INSERT ON axiom.risk_acceptance_requests TO axiom_runtime;
GRANT UPDATE (status, decided_by, decided_at, decision_rationale, acceptance_id, record_version)
  ON axiom.risk_acceptance_requests TO axiom_runtime;
GRANT UPDATE (reassessment_notified_at) ON axiom.risk_acceptances TO axiom_runtime;
