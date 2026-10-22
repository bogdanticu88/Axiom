-- 0008 R7 (approved by the project owner 2026-10-22, Option A with conditions): return from remediation to review.
--
--   remediation_planned -> review_required  authorised, recorded withdrawal decision with rationale
--   remediating -> review_required          only with verified evidence that no change was deployed
--   remediating -> awaiting_verification    (existing) for deployed, partially deployed or unknown changes, via an
--                                           "abandoned" remediation report; verification may return to review
-- Neither return may bypass an unresolved external effect. Proposals for the case are withdrawn and the case's plan
-- epoch advances, so an obsolete plan cannot later execute. Tickets, approvals, consumed uses, action history and
-- evidence are kept unchanged.

CREATE OR REPLACE FUNCTION axiom.case_transition_allowed(p_from text, p_to text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT (p_from, p_to) IN (
    ('received', 'investigating'),
    ('investigating', 'review_required'),
    ('review_required', 'investigating'),
    ('review_required', 'remediation_planned'),
    ('remediation_planned', 'remediating'),
    ('remediation_planned', 'review_required'),
    ('remediating', 'awaiting_verification'),
    ('remediating', 'review_required'),
    ('awaiting_verification', 'closed'),
    ('awaiting_verification', 'remediating'),
    ('awaiting_verification', 'review_required'),
    ('review_required', 'closed'),
    ('closed', 'investigating'))
$$;

ALTER TABLE axiom.finding_cases ADD COLUMN plan_epoch int NOT NULL DEFAULT 0;
GRANT UPDATE (plan_epoch) ON axiom.finding_cases TO axiom_runtime;

ALTER TABLE axiom.decisions DROP CONSTRAINT decisions_kind_check;
ALTER TABLE axiom.decisions ADD CONSTRAINT decisions_kind_check CHECK (kind IN ('investigation_start', 'assessment',
  'escalation', 'evidence_request', 'remediation_plan', 'external_work', 'remediation_report', 'verification_review',
  'deferral', 'closure', 'reopen', 'owner_assignment', 'risk_acceptance', 'remediation_withdrawal'));

-- Abandoned remediation reports: deployment state is recorded; an unknown deployment has no target to verify, so
-- its verification can only be inconclusive.
ALTER TABLE axiom.remediation_reports
  ADD COLUMN kind text NOT NULL DEFAULT 'change' CHECK (kind IN ('change', 'abandoned')),
  ADD COLUMN deployment_state text CHECK (deployment_state IN ('deployed', 'partial', 'unknown')),
  ALTER COLUMN target_asset_version_id DROP NOT NULL,
  ADD CONSTRAINT remediation_report_kind_state CHECK ((kind = 'change') = (deployment_state IS NULL)),
  ADD CONSTRAINT remediation_report_target_present CHECK (
    (kind = 'change' AND target_asset_version_id IS NOT NULL)
    OR (kind = 'abandoned' AND (deployment_state = 'unknown') = (target_asset_version_id IS NULL)));

CREATE OR REPLACE FUNCTION axiom.remediation_report_target() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.target_asset_version_id IS NULL THEN
    RETURN NEW;      -- abandoned with unknown deployment (CHECK above)
  END IF;
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

-- Database backstop for the R7 conditions, checked when the case event for the transition is written.
CREATE FUNCTION axiom.r7_return_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE d axiom.decisions;
BEGIN
  IF NOT (NEW.to_workflow = 'review_required' AND NEW.from_workflow IN ('remediation_planned', 'remediating'))
     AND NOT (NEW.from_workflow = 'remediating' AND NEW.to_workflow = 'awaiting_verification') THEN
    RETURN NEW;
  END IF;
  IF EXISTS (SELECT 1 FROM axiom.action_executions e JOIN axiom.action_proposals p
               ON p.tenant_id = e.tenant_id AND p.id = e.proposal_id
              WHERE p.tenant_id = NEW.tenant_id AND p.case_id = NEW.case_id
                AND e.state IN ('prepared', 'executing', 'reconciling')) THEN
    RAISE EXCEPTION 'unresolved external effect: reconcile or cancel executions before leaving remediation'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.to_workflow = 'awaiting_verification' THEN
    RETURN NEW;      -- the change-report path keeps its own guards
  END IF;
  SELECT * INTO d FROM axiom.decisions WHERE tenant_id = NEW.tenant_id AND id = NEW.decision_id;
  IF d.kind IS DISTINCT FROM 'remediation_withdrawal' THEN
    RAISE EXCEPTION 'returning to review from remediation requires a withdrawal decision' USING ERRCODE = '23514';
  END IF;
  IF NEW.from_workflow = 'remediating' AND (d.outcome <> 'no_change_deployed' OR NOT EXISTS (
       SELECT 1 FROM axiom.decision_evidence de JOIN axiom.evidence_objects ev
         ON ev.tenant_id = de.tenant_id AND ev.id = de.evidence_object_id
        WHERE de.tenant_id = NEW.tenant_id AND de.decision_id = d.id AND de.relation = 'supports'
          AND ev.status = 'verified')) THEN
    RAISE EXCEPTION 'leaving remediating directly for review needs verified evidence that no change was deployed'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER r7_return_guard BEFORE INSERT ON axiom.case_events FOR EACH ROW EXECUTE FUNCTION axiom.r7_return_guard();
