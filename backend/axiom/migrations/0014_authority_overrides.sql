-- 0014 Authority of system identities, and expiring priority overrides (ADR 0012 amendment, ADR 0011 amendment).

-- ---------------------------------------------------------------------------- decision authority
-- Replaces the 0013 guard, which allowed workload principals only 'reopen' and 'prioritisation' decisions and so
-- also blocked policy-authorised verification observations by a verification worker (VER-04).
--
-- Discretionary decisions stay human: assessment, escalation, evidence requests, remediation plans, deferral,
-- external work, change reports and withdrawals, every closure, risk acceptance, priority overrides, reopening on a
-- person's judgement, approvals and claim reviews.
--
-- A workload (system) principal may record exactly these policy-authorised results, each only with the authority
-- that permits it, recorded on the decision:
--   prioritisation       authority.permission = 'priority.apply'       deterministic policy result (incl. after an
--                                                                       override expires)
--   reopen               authority.system = true and the reason is recurrence or acceptance_expiry (expiry and
--                        recurrence events), or authority.permission = 'case.reopen'
--   verification_review  authority.permission = 'verification.record' a recorded verification observation; closing
--                                                                       the case still needs a person
-- The principal's kind is read from axiom.principals (trusted identity records) through axiom_auth.principal_kind; it is
-- never taken from the request, the token or the session context.
CREATE OR REPLACE FUNCTION axiom.human_decision_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  actor uuid;
  kind text;
  what text := TG_TABLE_NAME;
  allowed boolean := false;
BEGIN
  IF TG_TABLE_NAME = 'decisions' THEN
    actor := NEW.actor_principal_id;
    what := 'decision ' || NEW.kind;
  ELSIF TG_TABLE_NAME = 'approvals' THEN
    actor := NEW.approver_principal_id;
  ELSE
    actor := NEW.reviewer;
  END IF;
  kind := axiom_auth.principal_kind(actor);
  IF kind = 'human' THEN
    RETURN NEW;
  END IF;
  IF kind = 'workload' AND TG_TABLE_NAME = 'decisions' THEN
    -- COALESCE: a missing authority field yields NULL, and "IF NOT NULL" would not raise
    allowed := COALESCE(
               (NEW.kind = 'prioritisation' AND NEW.authority->>'permission' = 'priority.apply')
            OR (NEW.kind = 'verification_review' AND NEW.authority->>'permission' = 'verification.record')
            OR (NEW.kind = 'reopen' AND ((NEW.authority->>'system' = 'true'
                                          AND NEW.outcome IN ('recurrence', 'acceptance_expiry'))
                                         OR NEW.authority->>'permission' = 'case.reopen')), false);
  END IF;
  IF NOT allowed THEN
    RAISE EXCEPTION '% by a % principal is not a policy-authorised system result', what, COALESCE(kind, 'unknown')
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------- priority overrides
-- Every override has an expiry. When it expires the case is re-prioritised from current inputs under the current
-- policy by the system principal, with provenance; the earlier priority is never silently restored.
CREATE TABLE axiom.priority_overrides (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  case_id uuid NOT NULL,
  decision_id uuid NOT NULL,
  priority text NOT NULL CHECK (priority IN ('urgent', 'high', 'medium', 'low')),
  priority_before text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  end_reason text CHECK (end_reason IN ('expired', 'superseded', 'case_closed')),
  ended_by_decision_id uuid,
  record_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES axiom.finding_cases(tenant_id, id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES axiom.decisions(tenant_id, id),
  FOREIGN KEY (tenant_id, ended_by_decision_id) REFERENCES axiom.decisions(tenant_id, id),
  CHECK (expires_at > created_at),
  CHECK ((ended_at IS NULL) = (end_reason IS NULL))
);
CREATE UNIQUE INDEX priority_overrides_one_active ON axiom.priority_overrides(tenant_id, case_id) WHERE ended_at IS NULL;
CREATE INDEX priority_overrides_due ON axiom.priority_overrides(tenant_id, expires_at) WHERE ended_at IS NULL;

CREATE FUNCTION axiom.priority_overrides_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.id, NEW.case_id, NEW.decision_id, NEW.priority, NEW.priority_before, NEW.expires_at,
      NEW.created_by, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.id, OLD.case_id, OLD.decision_id, OLD.priority, OLD.priority_before,
                       OLD.expires_at, OLD.created_by, OLD.created_at) THEN
    RAISE EXCEPTION 'override terms are immutable; record a new override' USING ERRCODE = '42501';
  END IF;
  IF OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'an ended override is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'override record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER priority_overrides_guard BEFORE UPDATE ON axiom.priority_overrides
  FOR EACH ROW EXECUTE FUNCTION axiom.priority_overrides_guard();
CREATE TRIGGER priority_overrides_no_delete BEFORE DELETE ON axiom.priority_overrides
  FOR EACH ROW EXECUTE FUNCTION axiom.forbid_mutation();

INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('policy.preview', false, 'Preview the effect of a policy version on open cases without changing them');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('policy_admin', 'policy.preview'), ('analyst', 'policy.preview')
ON CONFLICT DO NOTHING;

SELECT axiom.apply_tenant_policy('priority_overrides');
GRANT SELECT, INSERT ON axiom.priority_overrides TO axiom_runtime;
GRANT UPDATE (ended_at, end_reason, ended_by_decision_id, record_version) ON axiom.priority_overrides TO axiom_runtime;
