"""Transactional case commands.

Each public method is one domain command executed inside the caller's
tenant-bound transaction (``Database.tenant_tx``). A command:

1. loads the case and checks the caller's expected version (optimistic concurrency);
2. checks permission at the case scope and separation-of-duty rules;
3. loads every guard input from authoritative rows (never client booleans);
4. writes decision, dependent records, audit event, versioned case update,
   case event and outbox message in the same transaction.

If any step fails the transaction rolls back and no partial state commits.
There is deliberately no generic "set workflow" operation.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...access import Authority, Authorizer, PermissionDenied, priority_rank
from ...db import TenantContext
from ...errors import Conflict, Forbidden, NotFound, ValidationFailed
from . import model
from .model import Assessment, ClosureReason, ReopenReason, Workflow

EVIDENCE_READ = {"internal": "evidence.read:internal", "confidential": "evidence.read:confidential",
                 "restricted": "evidence.read:restricted"}
MAX_DEFERRAL = timedelta(days=365)


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: UUID
    relation: str = "supports"   # supports | contradicts | context


@dataclass
class _Plan:
    """Everything one command writes, assembled before the versioned update."""
    to_workflow: Workflow
    event_type: str
    decision_kind: str | None = None
    decision_outcome: str | None = None
    rationale: str | None = None
    limitations: str | None = None
    authority: Authority | None = None
    evidence: Sequence[EvidenceRef] = ()
    changes: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    # Called with (decision_id, new_sequence) after the decision is inserted.
    dependents: Callable[[UUID | None, int], dict[str, Any]] | None = None
    topic: str = "case.transitioned"
    policy_version_id: UUID | None = None
    evidence_snapshot_id: UUID | None = None
    investigation_run_id: UUID | None = None
    # A deterministic result recorded by the tenant's system principal (recurrence, acceptance expiry). It still
    # needs a real permission (``authority``); the flag only labels the decision for readers.
    system_result: bool = False


class CaseService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn = conn
        self.ctx = ctx
        self.authz = authz

    # ------------------------------------------------------------------ queries
    def get(self, case_id: UUID) -> dict:
        case = self._load(case_id)
        self.authz.require("case.read", case["scope_id"])
        return case

    def list(self, *, workflow: str | None = None, limit: int = 50,
             after: tuple[datetime, UUID] | None = None) -> list[dict]:
        scopes = self.authz.readable_scopes("case.read")
        if not scopes:
            return []
        params: dict[str, Any] = {"scopes": scopes, "limit": min(max(limit, 1), 200)}
        where = ["c.scope_id IN (SELECT id FROM covered)"]
        if workflow:
            where.append("c.workflow = %(workflow)s")
            params["workflow"] = workflow
        if after:
            where.append("(c.created_at, c.id) > (%(after_ts)s, %(after_id)s)")
            params["after_ts"], params["after_id"] = after
        return list(self.conn.execute(
            f"""WITH RECURSIVE covered(id) AS (
                    SELECT id FROM axiom.scopes WHERE id = ANY(%(scopes)s)
                    UNION SELECT s.id FROM axiom.scopes s JOIN covered ON s.parent_id = covered.id)
                SELECT c.* FROM axiom.finding_cases c WHERE {' AND '.join(where)}
                ORDER BY c.created_at, c.id LIMIT %(limit)s""", params))

    def history(self, case_id: UUID) -> dict:
        case = self.get(case_id)
        events = list(self.conn.execute(
            "SELECT * FROM axiom.case_events WHERE case_id = %s ORDER BY sequence", (case_id,)))
        decisions = list(self.conn.execute(
            """SELECT d.*, COALESCE((SELECT jsonb_agg(jsonb_build_object('evidence_id', de.evidence_object_id,
                      'relation', de.relation)) FROM axiom.decision_evidence de
                      WHERE de.tenant_id = d.tenant_id AND de.decision_id = d.id), '[]') AS evidence
                 FROM axiom.decisions d WHERE d.case_id = %s ORDER BY d.recorded_at, d.id""", (case_id,)))
        closures = list(self.conn.execute(
            "SELECT * FROM axiom.closure_records WHERE case_id = %s ORDER BY case_event_sequence", (case_id,)))
        verifications = list(self.conn.execute(
            "SELECT * FROM axiom.verification_runs WHERE case_id = %s ORDER BY recorded_at", (case_id,)))
        return {"case": case, "events": events, "decisions": decisions, "closures": closures,
                "verifications": verifications}

    # ----------------------------------------------------------------- creation
    def create(self, *, scope_id: UUID, title: str, occurrence_ids: Sequence[UUID] = ()) -> dict:
        authority = self.authz.require("case.create", scope_id)
        case_id = uuid.uuid4()
        self.conn.execute(
            """INSERT INTO axiom.finding_cases(tenant_id, id, scope_id, title, workflow, assessment, priority,
                   disposition, record_version) VALUES (%s, %s, %s, %s, 'received', 'unassessed',
                   'pending', 'unset', 0)""",
            (self.ctx.tenant_id, case_id, scope_id, title))
        for occurrence_id in occurrence_ids:
            self._link_occurrence(case_id, occurrence_id)
        audit_id = audit.record(self.conn, self.ctx, action="case.create", resource_type="finding_case",
                                resource_id=case_id, detail={"authority": authority.as_json(),
                                                             "occurrences": [str(o) for o in occurrence_ids]})
        self._insert_event(case_id, 0, "case.created", None, Workflow.RECEIVED, None, audit_id,
                           {"title": title})
        outbox.enqueue(self.conn, self.ctx, topic="case.created", aggregate_type="finding_case",
                       aggregate_id=case_id, payload={"case_id": str(case_id), "version": 0})
        return self._load(case_id)

    def link_occurrence(self, case_id: UUID, expected_version: int, occurrence_id: UUID,
                        rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        authority = self.authz.require("case.create", case["scope_id"])
        if case["workflow"] == Workflow.CLOSED:
            raise Conflict("reopen the case before changing its occurrences", code="invalid_state")
        self._link_occurrence(case_id, occurrence_id)
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow(case["workflow"]), event_type="case.occurrence_linked",
            rationale=rationale, authority=authority, payload={"occurrence_id": str(occurrence_id)}))

    # --------------------------------------------------------------- investigation
    def start_investigation(self, case_id: UUID, expected_version: int, rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.RECEIVED)
        authority = self.authz.require("investigation.request", case["scope_id"])
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.INVESTIGATING, event_type="case.investigation_started",
            decision_kind="investigation_start", decision_outcome="scheduled", rationale=rationale,
            authority=authority))

    def record_assessment(self, case_id: UUID, expected_version: int, *, assessment: str, rationale: str,
                          limitations: str, evidence: Sequence[EvidenceRef],
                          evidence_snapshot_id: UUID | None = None, investigation_run_id: UUID | None = None) -> dict:
        """A human assessment. It may cite a frozen evidence snapshot and an investigation run (ADR 0012); the run's
        findings are analysis only: every claim the run did not reject must have been reviewed by a person first, and
        the run's limitations, contradictions and gaps are appended to the decision's limitations."""
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.INVESTIGATING)
        authority = self.authz.require("assessment.record", case["scope_id"])
        value = Assessment(assessment)
        if value is Assessment.UNASSESSED:
            raise ValidationFailed("an assessment outcome is required")
        if not limitations or not limitations.strip():
            raise ValidationFailed("record the assessment's limitations (state 'none identified' explicitly)")
        if model.assessment_needs_evidence(value) and not any(e.relation == "supports" for e in evidence):
            raise Conflict("a definite assessment requires verified supporting evidence; "
                           "record 'inconclusive' when evidence is missing", code="evidence_required")
        notes = []
        if investigation_run_id is not None:
            run = self.conn.execute("SELECT * FROM axiom.investigation_runs WHERE id = %s AND case_id = %s",
                                    (investigation_run_id, case_id)).fetchone()
            if run is None:
                raise NotFound("investigation not found for this case", code="investigation_not_found")
            if run["status"] not in ("completed", "incomplete"):
                raise Conflict(f"investigation is {run['status']}", code="investigation_not_usable")
            if evidence_snapshot_id is not None and evidence_snapshot_id != run["snapshot_id"]:
                raise Conflict("the snapshot must be the investigation's snapshot", code="snapshot_mismatch")
            evidence_snapshot_id = run["snapshot_id"]
            unreviewed = self.conn.execute(
                """SELECT count(*) AS n FROM axiom.investigation_claims c WHERE c.run_id = %s AND c.validation <> 'rejected'
                     AND NOT EXISTS (SELECT 1 FROM axiom.claim_reviews r WHERE r.claim_id = c.id)""",
                (investigation_run_id,)).fetchone()["n"]
            if unreviewed:
                raise Conflict(f"{unreviewed} investigation claim(s) have not been reviewed by a person",
                               code="claims_not_reviewed")
            notes.append(f"investigation {investigation_run_id} {run['status']}"
                         + (f" ({run['outcome_reason']})" if run["outcome_reason"] else "")
                         + "; AI analysis reviewed by a person, not authoritative")
            notes += [lim["message"] for lim in run["limitations"]]
        if evidence_snapshot_id is not None:
            snap = self.conn.execute("SELECT * FROM axiom.evidence_snapshots WHERE id = %s AND case_id = %s",
                                     (evidence_snapshot_id, case_id)).fetchone()
            if snap is None:
                raise NotFound("snapshot not found for this case", code="snapshot_not_found")
            notes.append(f"evidence snapshot {snap['id']} ({snap['digest'][:12]}): "
                         f"{len(snap['contradictions'])} recorded contradiction(s), {len(snap['gaps'])} gap(s)")
        full_limitations = limitations if not notes else limitations.rstrip() + " | " + "; ".join(notes)
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.REVIEW, event_type="case.assessed", decision_kind="assessment",
            decision_outcome=value.value, rationale=rationale, limitations=full_limitations[:10000],
            authority=authority, evidence=evidence, changes={"assessment": value.value},
            payload={"evidence_snapshot_id": str(evidence_snapshot_id) if evidence_snapshot_id else None,
                     "investigation_run_id": str(investigation_run_id) if investigation_run_id else None},
            evidence_snapshot_id=evidence_snapshot_id, investigation_run_id=investigation_run_id))

    def escalate(self, case_id: UUID, expected_version: int, rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.INVESTIGATING)
        authority = self.authz.require("investigation.request", case["scope_id"])
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.REVIEW, event_type="case.escalated", decision_kind="escalation",
            decision_outcome="escalated", rationale=rationale, authority=authority))

    def request_more_evidence(self, case_id: UUID, expected_version: int, rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("investigation.request", case["scope_id"])
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.INVESTIGATING, event_type="case.evidence_requested",
            decision_kind="evidence_request", decision_outcome="more_evidence", rationale=rationale,
            authority=authority, changes={"disposition": "unset", "review_at": None}))

    # ---------------------------------------------------------------- remediation
    def plan_remediation(self, case_id: UUID, expected_version: int, *, owner_principal_id: UUID,
                         rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("remediation.propose", case["scope_id"])
        if not self.authz.has("remediation.update", case["scope_id"], principal_id=owner_principal_id):
            raise Conflict("assigned owner lacks remediation authority for this scope",
                           code="owner_not_eligible")
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.PLANNED, event_type="case.remediation_planned",
            decision_kind="remediation_plan", decision_outcome="remediate", rationale=rationale,
            authority=authority, changes={"disposition": "remediate", "owner_principal_id": owner_principal_id,
                                          "review_at": None},
            payload={"owner_principal_id": str(owner_principal_id)}))

    def defer(self, case_id: UUID, expected_version: int, *, review_at: datetime, rationale: str,
              pause_reason: str | None = None) -> dict:
        """Defer with a review date. The remediation SLA clock pauses only when ``pause_reason`` is one of the
        reasons the published SLA policy authorises; otherwise time keeps counting (deferral does not erase
        accountability). Gross, paused and adjusted time are reported separately."""
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("remediation.propose", case["scope_id"])
        now = self.authz.now()
        if review_at.tzinfo is None or not (now < review_at <= now + MAX_DEFERRAL):
            raise ValidationFailed("review date must be in the future and within 365 days")
        payload = {"review_at": review_at.isoformat()}
        if pause_reason is not None:
            from ..policies.service import current
            sla, sla_id, _ = current(self.conn, "sla")
            if pause_reason not in sla.get("pause_reasons", []):
                raise ValidationFailed(f"pause reason must be one of {sla.get('pause_reasons', [])}",
                                       code="pause_reason_not_authorised")
            payload.update(pause_reason=pause_reason, sla_policy_version_id=str(sla_id) if sla_id else None)
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.REVIEW, event_type="case.deferred", decision_kind="deferral",
            decision_outcome="defer", rationale=rationale, authority=authority,
            changes={"disposition": "defer", "review_at": review_at}, payload=payload))

    def record_external_work(self, case_id: UUID, expected_version: int, *, external_reference: str,
                             rationale: str) -> dict:
        """remediation_planned -> remediating on recorded externally initiated work.

        The approved-action path (Phase D) will be a second route into 'remediating'.
        """
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.PLANNED)
        authority = self._owner_or_propose(case)
        if not external_reference.strip():
            raise ValidationFailed("external work reference required")
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.REMEDIATING, event_type="case.remediation_started",
            decision_kind="external_work", decision_outcome="external_work_recorded", rationale=rationale,
            authority=authority, payload={"external_reference": external_reference}))

    def report_change(self, case_id: UUID, expected_version: int, *, target_asset_version_id: UUID,
                      change_reference: str, rationale: str, evidence_id: UUID | None = None) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REMEDIATING)
        authority = self._owner_or_propose(case)
        if not self._exists("asset_versions", target_asset_version_id):
            raise NotFound("deployment not found", code="asset_version_not_found")
        evidence = [EvidenceRef(evidence_id, "supports")] if evidence_id else []
        report_id = uuid.uuid4()

        def dependents(decision_id: UUID | None, _seq: int) -> dict:
            self.conn.execute(
                """INSERT INTO axiom.remediation_reports(tenant_id, id, case_id, target_asset_version_id,
                       change_reference, evidence_object_id, reported_by, decision_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (self.ctx.tenant_id, report_id, case_id, target_asset_version_id, change_reference,
                 evidence_id, self.ctx.principal_id, decision_id))
            return {"remediation_report_id": str(report_id)}

        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.VERIFYING, event_type="case.change_reported",
            decision_kind="remediation_report", decision_outcome="change_reported", rationale=rationale,
            authority=authority, evidence=evidence, dependents=dependents,
            payload={"target_asset_version_id": str(target_asset_version_id)}))

    def withdraw_remediation(self, case_id: UUID, expected_version: int, *, rationale: str,
                             deployment_state: str | None = None, evidence: Sequence[EvidenceRef] = (),
                             target_asset_version_id: UUID | None = None,
                             change_reference: str | None = None) -> dict:
        """R7 (approved 2026-10-22): leave remediation when a plan is abandoned.

        * from remediation_planned: back to review through an authorised, recorded decision;
        * from remediating with ``deployment_state='none'``: back to review only with verified evidence that no
          change was deployed;
        * from remediating with ``deployed`` / ``partial`` / ``unknown``: to verification through an abandoned
          remediation report (unknown has no target, so verification can only be inconclusive and returns to review).
        Unresolved external effects block every route. Open proposals for the case are withdrawn and the plan epoch
        advances, so an obsolete plan cannot execute later. Tickets, approvals, consumed uses and evidence are kept.
        """
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        if case["workflow"] not in (Workflow.PLANNED, Workflow.REMEDIATING):
            raise Conflict("only planned or in-progress remediation can be withdrawn", code="invalid_state")
        if case["workflow"] == Workflow.PLANNED:
            authority = self.authz.require("remediation.propose", case["scope_id"])
            if deployment_state not in (None, "none"):
                raise ValidationFailed("nothing is deployed while remediation is only planned")
        else:
            authority = self._owner_or_propose(case)
            if deployment_state not in ("none", "deployed", "partial", "unknown"):
                raise ValidationFailed("deployment_state must be none, deployed, partial or unknown")
        unresolved = [str(r["id"]) for r in self.conn.execute(
            """SELECT e.id FROM axiom.action_executions e JOIN axiom.action_proposals p ON p.id = e.proposal_id
                WHERE p.case_id = %s AND e.state IN ('prepared', 'executing', 'reconciling')""", (case_id,))]
        if unresolved:
            raise Conflict("reconcile or cancel external actions before leaving remediation",
                           code="unresolved_external_effect", details={"execution_ids": unresolved})
        withdrawn = self._withdraw_proposals(case_id, rationale)
        common = {"changes": {"disposition": "unset", "review_at": None, "plan_epoch": case["plan_epoch"] + 1}}
        payload = {"withdrawn_proposals": withdrawn, "deployment_state": deployment_state or "none"}
        if case["workflow"] == Workflow.PLANNED:
            return self._apply(case, expected_version, _Plan(
                to_workflow=Workflow.REVIEW, event_type="case.remediation_withdrawn",
                decision_kind="remediation_withdrawal", decision_outcome="plan_withdrawn", rationale=rationale,
                authority=authority, evidence=evidence, payload=payload, **common))
        if deployment_state == "none":
            if not any(ref.relation == "supports" for ref in evidence):
                raise ValidationFailed("evidence that no change was deployed is required", code="evidence_required")
            return self._apply(case, expected_version, _Plan(
                to_workflow=Workflow.REVIEW, event_type="case.remediation_withdrawn",
                decision_kind="remediation_withdrawal", decision_outcome="no_change_deployed", rationale=rationale,
                authority=authority, evidence=evidence, payload=payload, **common))
        if deployment_state == "unknown" and target_asset_version_id is not None:
            raise ValidationFailed("an unknown deployment has no target; use deployed or partial with a target")
        if deployment_state != "unknown" and target_asset_version_id is None:
            raise ValidationFailed("identify the deployment to verify, or use deployment_state=unknown")
        report_id = uuid.uuid4()

        def dependents(decision_id: UUID | None, _seq: int) -> dict:
            self.conn.execute(
                """INSERT INTO axiom.remediation_reports(tenant_id, id, case_id, target_asset_version_id,
                       change_reference, reported_by, decision_id, kind, deployment_state)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'abandoned', %s)""",
                (self.ctx.tenant_id, report_id, case_id, target_asset_version_id,
                 change_reference or "remediation abandoned", self.ctx.principal_id, decision_id, deployment_state))
            return {"remediation_report_id": str(report_id)}
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.VERIFYING, event_type="case.remediation_abandoned",
            decision_kind="remediation_report", decision_outcome="remediation_abandoned", rationale=rationale,
            authority=authority, evidence=evidence, dependents=dependents, payload=payload, **common))

    def _withdraw_proposals(self, case_id: UUID, reason: str) -> list[str]:
        ids = []
        for p in self.conn.execute("SELECT id FROM axiom.action_proposals WHERE case_id = %s AND status = 'open' "
                                   "FOR UPDATE", (case_id,)).fetchall():
            self.conn.execute("""UPDATE axiom.action_proposals SET status = 'withdrawn',
                                        record_version = record_version + 1 WHERE id = %s""", (p["id"],))
            audit.record(self.conn, self.ctx, action="action.withdrawn", resource_type="action_proposal",
                         resource_id=p["id"], detail={"reason": f"remediation withdrawn: {reason}",
                                                      "by_case_transition": True})
            ids.append(str(p["id"]))
        return ids

    # ---------------------------------------------------------------- verification
    def record_verification(self, case_id: UUID, expected_version: int, *, claimed_result: str,
                            coverage: str, criteria: dict, rationale: str,
                            observed_asset_version_id: UUID | None = None,
                            observed_deployment_digest: str | None = None,
                            evidence_id: UUID | None = None) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.VERIFYING)
        authority = self.authz.require("verification.record", case["scope_id"])
        if coverage not in ("complete", "partial", "none"):
            raise ValidationFailed("coverage must be complete, partial or none")
        if not criteria:
            raise ValidationFailed("explicit acceptance criteria are required")
        report = self._latest_report(case_id)
        if report is None:
            raise Conflict("no reported change to verify", code="no_remediation_report")
        if report["reported_by"] == self.ctx.principal_id:
            raise Forbidden("the person who reported the change cannot verify it",
                            code="separation_of_duties")
        target = self.conn.execute("SELECT * FROM axiom.asset_versions WHERE id = %s",
                                   (report["target_asset_version_id"],)).fetchone()
        if target is None:      # abandoned remediation with unknown deployment: nothing identifiable to verify
            observed = None
        else:
            observed = self._resolve_observed_version(target, observed_asset_version_id, observed_deployment_digest)
        matches = None if observed is None else (observed["id"] == target["id"])
        evidence_ok = False
        if evidence_id is not None:
            ev = self._evidence_for_citation(evidence_id)
            evidence_ok = ev["status"] == "verified"
        outcome, reason = model.verification_outcome(
            claimed=claimed_result, coverage=coverage, observed_matches_target=matches,
            evidence_verified=evidence_ok)
        criteria_json = json.dumps(criteria, sort_keys=True, separators=(",", ":"))
        run_id = uuid.uuid4()
        to_workflow = model.workflow_after_verification(outcome)
        if report["kind"] == "abandoned" and to_workflow == Workflow.REMEDIATING:
            to_workflow = Workflow.REVIEW     # R7: the plan was abandoned, so a failed check goes back to review

        def dependents(decision_id: UUID | None, _seq: int) -> dict:
            self.conn.execute(
                """INSERT INTO axiom.verification_runs(tenant_id, id, case_id, remediation_report_id,
                       observed_asset_version_id, criteria, criteria_digest, coverage, outcome,
                       outcome_reason, evidence_object_id, recorded_by, decision_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (self.ctx.tenant_id, run_id, case_id, report["id"], observed["id"] if observed else None,
                 Jsonb(criteria), hashlib.sha256(criteria_json.encode()).hexdigest(), coverage, outcome,
                 reason, evidence_id if evidence_ok else None, self.ctx.principal_id, decision_id))
            return {"verification_run_id": str(run_id), "outcome": outcome, "outcome_reason": reason}

        evidence = [EvidenceRef(evidence_id, "supports")] if evidence_ok else []
        return self._apply(case, expected_version, _Plan(
            to_workflow=to_workflow, event_type=f"case.verification_{outcome}",
            decision_kind="verification_review", decision_outcome=outcome, rationale=rationale,
            authority=authority, evidence=evidence, dependents=dependents))

    # -------------------------------------------------------------------- closure
    def close_verified(self, case_id: UUID, expected_version: int, *, verification_run_id: UUID,
                       rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.VERIFYING)
        authority = self.authz.require("closure.propose", case["scope_id"])
        if case["assessment"] != Assessment.SUPPORTED:
            raise Conflict(f"a case assessed {case['assessment']} cannot close as verified remediated",
                           code="assessment_not_supported")
        run = self.conn.execute("SELECT * FROM axiom.verification_runs WHERE id = %s AND case_id = %s",
                                (verification_run_id, case_id)).fetchone()
        report = self._latest_report(case_id)
        if run is None:
            raise NotFound("verification run not found")
        if run["outcome"] != "passed" or report is None or run["remediation_report_id"] != report["id"]:
            raise Conflict("closure requires a passed verification of the latest reported change",
                           code="verification_not_passed")
        if report["reported_by"] == self.ctx.principal_id:
            raise Forbidden("the person who reported the change cannot close it", code="separation_of_duties")
        return self._close(case, expected_version, ClosureReason.VERIFIED_REMEDIATED, rationale, authority,
                           disposition="remediate", verification_run_id=verification_run_id)

    def dismiss(self, case_id: UUID, expected_version: int, *, rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("case.dismiss", case["scope_id"])
        if case["assessment"] != Assessment.NOT_SUPPORTED:
            raise Conflict("dismissal requires a not_supported assessment", code="assessment_required")
        assessment = self.conn.execute(
            """SELECT d.*, EXISTS (SELECT 1 FROM axiom.decision_evidence de WHERE de.tenant_id = d.tenant_id
                   AND de.decision_id = d.id AND de.relation = 'supports') AS has_evidence
                 FROM axiom.decisions d WHERE d.case_id = %s AND d.kind = 'assessment'
                ORDER BY d.recorded_at DESC, d.id DESC LIMIT 1""", (case_id,)).fetchone()
        if assessment is None or not assessment["has_evidence"]:
            raise Conflict("dismissal requires an evidence-backed assessment", code="evidence_required")
        if assessment["actor_principal_id"] == self.ctx.principal_id:
            raise Forbidden("the assessor cannot approve their own dismissal", code="separation_of_duties")
        return self._close(case, expected_version, ClosureReason.DISMISSED, rationale, authority,
                           disposition="dismiss")

    def close_duplicate(self, case_id: UUID, expected_version: int, *, duplicate_of: UUID,
                        rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("closure.propose", case["scope_id"])
        if duplicate_of == case_id:
            raise ValidationFailed("a case cannot duplicate itself")
        target = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (duplicate_of,)).fetchone()
        if target is None:
            raise NotFound("duplicate target not found", code="case_not_found")
        self.authz.require("case.read", target["scope_id"])
        target_dup = self.conn.execute(
            """SELECT 1 FROM axiom.closure_records cr WHERE cr.case_id = %s AND cr.reason = 'duplicate'
                 AND cr.case_event_sequence = (SELECT record_version FROM axiom.finding_cases WHERE id = %s)""",
            (duplicate_of, duplicate_of)).fetchone()
        if target["workflow"] == Workflow.CLOSED and target_dup:
            raise Conflict("target is itself closed as a duplicate; link to the surviving case",
                           code="duplicate_chain")
        shared = self.conn.execute(
            """SELECT 1 FROM axiom.case_occurrence_links la
                 JOIN axiom.finding_occurrences oa ON oa.id = la.occurrence_id
                 JOIN axiom.asset_versions va ON va.id = oa.asset_version_id
                 JOIN axiom.finding_occurrences ob ON ob.vulnerability_ref = oa.vulnerability_ref
                 JOIN axiom.asset_versions vb ON vb.id = ob.asset_version_id AND vb.asset_id = va.asset_id
                 JOIN axiom.case_occurrence_links lb ON lb.occurrence_id = ob.id
                WHERE la.case_id = %s AND lb.case_id = %s AND la.unlinked_at IS NULL
                  AND lb.unlinked_at IS NULL AND oa.vulnerability_ref IS NOT NULL LIMIT 1""",
            (case_id, duplicate_of)).fetchone()
        if shared is None:
            raise Conflict("cases share no vulnerability on the same asset; duplicate not validated",
                           code="duplicate_not_validated")
        return self._close(case, expected_version, ClosureReason.DUPLICATE, rationale, authority,
                           disposition="duplicate", duplicate_of_case_id=duplicate_of)

    def close_asset_retired(self, case_id: UUID, expected_version: int, *, retirement_evidence_id: UUID,
                            rationale: str) -> dict:
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.REVIEW)
        authority = self.authz.require("closure.propose", case["scope_id"])
        ev = self._evidence_for_citation(retirement_evidence_id)
        if ev["status"] != "verified":
            raise Conflict("retirement evidence is not verified", code="evidence_not_verified")
        active = self.conn.execute(
            """SELECT count(*) FILTER (WHERE a.lifecycle_status <> 'retired') AS not_retired, count(*) AS total
                 FROM axiom.case_occurrence_links l JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
                 JOIN axiom.asset_versions v ON v.id = o.asset_version_id JOIN axiom.assets a ON a.id = v.asset_id
                WHERE l.case_id = %s AND l.unlinked_at IS NULL""", (case_id,)).fetchone()
        if active["total"] == 0 or active["not_retired"] > 0:
            raise Conflict("every affected asset must have recorded retirement", code="asset_not_retired")
        return self._close(case, expected_version, ClosureReason.ASSET_RETIRED, rationale, authority,
                           disposition=case["disposition"] if case["disposition"] != "defer" else "unset",
                           retirement_evidence_id=retirement_evidence_id,
                           evidence=[EvidenceRef(retirement_evidence_id, "supports")])

    def accept_risk(self, case_id: UUID, expected_version: int, *, expires_at: datetime, rationale: str,
                    compensating_controls: str | None = None) -> dict:
        """Single-call acceptance (request + self-authorisation). Allowed only where the risk policy does not require
        independent authorisation; otherwise use the request/authorise flow (``domains.cases.risk``)."""
        from .risk import RiskService
        return RiskService(self.conn, self.ctx, self.authz).accept_directly(
            case_id, expected_version, expires_at=expires_at, rationale=rationale,
            compensating_controls=compensating_controls)

    def reopen(self, case_id: UUID, expected_version: int, *, reason: str, rationale: str,
               system: bool = False) -> dict:
        reopen_reason = ReopenReason(reason)
        if reopen_reason is ReopenReason.ACCEPTANCE_EXPIRY and not system:
            raise ValidationFailed("acceptance expiry reopening is performed by the expiry process")
        if system and reopen_reason not in (ReopenReason.RECURRENCE, ReopenReason.ACCEPTANCE_EXPIRY):
            raise ValidationFailed("only recurrence and acceptance expiry are system reopen reasons")
        case = self._load(case_id)
        model.check_expected_version(case["record_version"], expected_version)
        model.require_state(case["workflow"], Workflow.CLOSED)
        # system results need the same permission as a person would: the system principal holds case.reopen
        authority = self.authz.require("case.reopen", case["scope_id"])
        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.INVESTIGATING, event_type="case.reopened", decision_kind="reopen",
            decision_outcome=reopen_reason.value, rationale=rationale, authority=authority, system_result=system,
            changes={"assessment": "unassessed", "disposition": "unset", "review_at": None},
            payload={"reason": reopen_reason.value}, topic="case.reopened"))

    # ------------------------------------------------------------------ internals
    def _close(self, case: dict, expected_version: int, reason: ClosureReason, rationale: str,
               authority: Authority, *, disposition: str, verification_run_id: UUID | None = None,
               risk_acceptance_id: UUID | None = None, duplicate_of_case_id: UUID | None = None,
               retirement_evidence_id: UUID | None = None, evidence: Sequence[EvidenceRef] = (),
               pre_dependents: Callable[[UUID | None, int], dict] | None = None,
               decision_kind: str = "closure") -> dict:
        model.require_state(case["workflow"], model.closure_origin(reason))
        closure_id = uuid.uuid4()

        def dependents(decision_id: UUID | None, seq: int) -> dict:
            extra = pre_dependents(decision_id, seq) if pre_dependents else {}
            self.conn.execute(
                """INSERT INTO axiom.closure_records(tenant_id, id, case_id, case_event_sequence, reason,
                       decision_id, verification_run_id, risk_acceptance_id, duplicate_of_case_id,
                       retirement_evidence_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (self.ctx.tenant_id, closure_id, case["id"], seq, reason.value, decision_id,
                 verification_run_id, risk_acceptance_id, duplicate_of_case_id, retirement_evidence_id))
            return {**extra, "closure_id": str(closure_id), "closure_reason": reason.value}

        return self._apply(case, expected_version, _Plan(
            to_workflow=Workflow.CLOSED, event_type=f"case.closed.{reason.value}", decision_kind=decision_kind,
            decision_outcome=reason.value, rationale=rationale, authority=authority, evidence=evidence,
            changes={"disposition": disposition, "review_at": None}, dependents=dependents,
            topic="case.closed"))

    def _apply(self, case: dict, expected_version: int, plan: _Plan) -> dict:
        model.check_expected_version(case["record_version"], expected_version)
        if plan.to_workflow != case["workflow"]:
            model.check_transition(case["workflow"], plan.to_workflow)
        if not (plan.rationale or "").strip():
            raise ValidationFailed("a rationale is required")
        new_version = expected_version + 1
        for ref in plan.evidence:
            if ref.relation not in ("supports", "contradicts", "context"):
                raise ValidationFailed("invalid evidence relation")
            ev = self._evidence_for_citation(ref.evidence_id)
            if ev["status"] != "verified":
                raise Conflict("only verified evidence can support a decision", code="evidence_not_verified",
                               details={"evidence_id": str(ref.evidence_id)})

        decision_id = None
        if plan.decision_kind:
            decision_id = uuid.uuid4()
            # system results record the actor's kind as held in the identity records, not as claimed by the context
            if plan.authority is None:
                raise ValidationFailed("a decision needs the authority it relies on")
            authority_json = plan.authority.as_json()
            if plan.system_result:
                authority_json |= {"system": True, "principal_kind": self.conn.execute(
                    "SELECT axiom_auth.principal_kind(%s) AS k", (self.ctx.principal_id,)).fetchone()["k"]}
            self.conn.execute(
                """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, limitations,
                       actor_principal_id, authority, policy_version_id, evidence_snapshot_id, investigation_run_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (self.ctx.tenant_id, decision_id, case["id"], plan.decision_kind, plan.decision_outcome,
                 plan.rationale, plan.limitations, self.ctx.principal_id, Jsonb(authority_json),
                 plan.policy_version_id, plan.evidence_snapshot_id, plan.investigation_run_id))
            for ref in plan.evidence:
                self.conn.execute(
                    """INSERT INTO axiom.decision_evidence(tenant_id, decision_id, evidence_object_id, relation)
                       VALUES (%s, %s, %s, %s)""", (self.ctx.tenant_id, decision_id, ref.evidence_id, ref.relation))
        extra = plan.dependents(decision_id, new_version) if plan.dependents else {}
        payload = {**plan.payload, **extra}

        audit_id = audit.record(
            self.conn, self.ctx, action=plan.event_type, resource_type="finding_case", resource_id=case["id"],
            detail={"from": case["workflow"], "to": plan.to_workflow.value, "version": new_version,
                    "decision_id": str(decision_id) if decision_id else None,
                    "authority": plan.authority.as_json() if plan.authority else None, **payload})

        assignments = {"workflow": plan.to_workflow.value, **plan.changes}
        columns = ", ".join(f"{name} = %({name})s" for name in assignments)
        updated = self.conn.execute(
            f"""UPDATE axiom.finding_cases SET {columns}, record_version = record_version + 1,
                    updated_at = clock_timestamp()
                 WHERE id = %(case_id)s AND record_version = %(expected)s RETURNING *""",
            {**assignments, "case_id": case["id"], "expected": expected_version}).fetchone()
        if updated is None:
            raise Conflict("case was changed by another request", code="stale_version")
        self._insert_event(case["id"], new_version, plan.event_type, case["workflow"], plan.to_workflow,
                           decision_id, audit_id, payload)
        outbox.enqueue(self.conn, self.ctx, topic=plan.topic, aggregate_type="finding_case",
                       aggregate_id=case["id"],
                       payload={"case_id": str(case["id"]), "version": new_version, "event": plan.event_type,
                                "from": case["workflow"], "to": plan.to_workflow.value})
        return updated

    def _insert_event(self, case_id: UUID, sequence: int, event_type: str, from_workflow: str | None,
                      to_workflow: Workflow, decision_id: UUID | None, audit_id: UUID, payload: dict) -> None:
        self.conn.execute(
            """INSERT INTO axiom.case_events(tenant_id, id, case_id, sequence, event_type, from_workflow,
                   to_workflow, actor_principal_id, decision_id, audit_event_id, correlation_id, payload)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (self.ctx.tenant_id, uuid.uuid4(), case_id, sequence, event_type, from_workflow, to_workflow.value,
             self.ctx.principal_id, decision_id, audit_id, self.ctx.correlation_id, Jsonb(payload)))

    def _load(self, case_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
        if row is None:
            # RLS makes other tenants' cases indistinguishable from nonexistent ones.
            raise NotFound("case not found", code="case_not_found")
        return row

    def _exists(self, table: str, row_id: UUID) -> bool:
        assert table in {"asset_versions", "finding_occurrences", "finding_cases"}
        return self.conn.execute(f"SELECT 1 FROM axiom.{table} WHERE id = %s", (row_id,)).fetchone() is not None

    def _link_occurrence(self, case_id: UUID, occurrence_id: UUID) -> None:
        if not self._exists("finding_occurrences", occurrence_id):
            raise NotFound("occurrence not found", code="occurrence_not_found")
        self.conn.execute(
            """INSERT INTO axiom.case_occurrence_links(tenant_id, case_id, occurrence_id, linked_by)
               VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING""",
            (self.ctx.tenant_id, case_id, occurrence_id, self.ctx.principal_id))

    def _evidence_for_citation(self, evidence_id: UUID) -> dict:
        ev = self.conn.execute("SELECT id, status, scope_id, classification FROM axiom.evidence_objects WHERE id = %s",
                               (evidence_id,)).fetchone()
        if ev is None:
            raise NotFound("evidence not found", code="evidence_not_found")
        # Citing evidence requires being allowed to read it at its classification.
        self.authz.require(EVIDENCE_READ[ev["classification"]], ev["scope_id"])
        return ev

    def _latest_report(self, case_id: UUID) -> dict | None:
        return self.conn.execute(
            "SELECT * FROM axiom.remediation_reports WHERE case_id = %s ORDER BY created_at DESC, id DESC LIMIT 1",
            (case_id,)).fetchone()

    def _resolve_observed_version(self, target: dict, observed_id: UUID | None, digest: str | None) -> dict | None:
        if observed_id is not None:
            row = self.conn.execute("SELECT * FROM axiom.asset_versions WHERE id = %s", (observed_id,)).fetchone()
            if row is None:
                raise NotFound("observed deployment not found", code="asset_version_not_found")
            return row
        if digest:
            rows = self.conn.execute(
                "SELECT * FROM axiom.asset_versions WHERE asset_id = %s AND deployment_digest = %s",
                (target["asset_id"], digest)).fetchall()
            if len(rows) == 1:
                return rows[0]
            if not rows:
                # A digest not recorded for this asset cannot be the reported deployment.
                return {"id": None, "asset_id": target["asset_id"], "deployment_digest": digest}
        return None

    def _owner_or_propose(self, case: dict) -> Authority:
        if case["owner_principal_id"] == self.ctx.principal_id:
            return self.authz.require("remediation.update", case["scope_id"])
        try:
            return self.authz.require("remediation.propose", case["scope_id"])
        except PermissionDenied:
            raise PermissionDenied("only the assigned owner or an analyst may update remediation") from None

    def _delegation_limit(self, action_class: str, case: dict, now: datetime, expires_at: datetime) -> dict:
        lineage = self.authz.scope_lineage(case["scope_id"])
        rows = self.conn.execute(
            """SELECT * FROM axiom.delegation_limits WHERE principal_id = %s AND action_class = %s
                 AND revoked_at IS NULL AND scope_id = ANY(%s)""",
            (self.ctx.principal_id, action_class, list(lineage))).fetchall()
        needed_rank = priority_rank(case["priority"])
        for row in rows:
            if (priority_rank(row["max_priority"]) >= needed_rank
                    and expires_at <= now + timedelta(days=row["max_duration_days"])):
                return row
        raise Forbidden("outside delegated risk acceptance limits", code="delegation_limit_exceeded",
                        details={"case_priority": case["priority"]})


def expire_risk_acceptances(conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer) -> list[UUID]:
    """System sweep for one tenant: expire due acceptances and reopen the cases they closed (A11).

    Runs as the tenant's system workload principal. Idempotent: already-expired
    acceptances are not selected; concurrent sweeps skip locked rows.
    """
    service = CaseService(conn, ctx, authz)
    expired: list[UUID] = []
    due = conn.execute(
        """SELECT * FROM axiom.risk_acceptances WHERE status = 'active' AND expires_at <= clock_timestamp()
           ORDER BY expires_at FOR UPDATE SKIP LOCKED""").fetchall()
    for acceptance in due:
        conn.execute(
            """UPDATE axiom.risk_acceptances SET status = 'expired', ended_at = clock_timestamp(),
                      record_version = record_version + 1 WHERE id = %s""", (acceptance["id"],))
        audit.record(conn, ctx, action="risk_acceptance.expired", resource_type="risk_acceptance",
                     resource_id=acceptance["id"], detail={"case_id": str(acceptance["case_id"])})
        outbox.enqueue(conn, ctx, topic="risk_acceptance.expired", aggregate_type="risk_acceptance",
                       aggregate_id=acceptance["id"],
                       payload={"case_id": str(acceptance["case_id"]),
                                "notify_principal_id": str(acceptance["owner_principal_id"])})
        case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s FOR UPDATE",
                            (acceptance["case_id"],)).fetchone()
        current_closure = conn.execute(
            "SELECT * FROM axiom.closure_records WHERE case_id = %s AND case_event_sequence = %s",
            (case["id"], case["record_version"])).fetchone()
        root = acceptance
        while root["renewal_of"] is not None:      # renewals supersede, the closure keeps the original
            root = conn.execute("SELECT * FROM axiom.risk_acceptances WHERE id = %s", (root["renewal_of"],)).fetchone()
        if (case["workflow"] == Workflow.CLOSED and current_closure is not None
                and current_closure["risk_acceptance_id"] == root["id"]):
            service.reopen(case["id"], case["record_version"], reason=ReopenReason.ACCEPTANCE_EXPIRY.value,
                           rationale=f"risk acceptance {acceptance['id']} expired", system=True)
        expired.append(acceptance["id"])
    return expired
