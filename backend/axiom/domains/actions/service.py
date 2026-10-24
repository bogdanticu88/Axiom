"""Action proposals, approvals, reservations and executions (Specification S 9, Plan S 7, Design S 7).

Protocol (Plan S 7):
1. ``propose`` / ``revise`` persist an immutable version; the database computes its binding digest.
2. ``decide`` records an approval bound to that exact version and digest, with expiry and a use count. Proposers
   cannot approve (service and database). Only the current version of an open proposal can be decided.
3. ``request_execution`` locks the proposal then the approval (always in that order), re-checks validity, reserves
   one use (counter + reservation row in the same transaction) and enqueues an execution job.
4. The job re-checks everything again at the effect boundary (``check_execution``) inside the effect gate's fenced
   transaction, records intent, executes and reconciles (``axiom.jobs.effects``).

A reserved use is never returned once the effect may have been attempted (database guard): timeouts do not restore
approvals. Operators can reconcile, retry or abandon an execution, but cannot extend or re-mint approval.

Cancelling an execution stops its scheduling; it does not establish that the external action was cancelled. The
outcome is decided from the effect evidence (``effect_evidence``, ``settle_cancellation``): an execution is cancelled,
and its use returned, only when the records show that no dispatch began; a recorded effect makes it succeeded; any
other case keeps the use reserved and parks the execution for an operator.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, Forbidden, NotFound, ValidationFailed
from ...jobs import Done, Fail, NeedsOperator, enqueue
from ...jobs.core import event, settle_cancelled_job
from ...jobs.effects import restore_doubt, unaccounted_dispatches
from .model import canonical_ticket_payload, effect_class

EXECUTE_KIND = "action.execute"
TERMINAL_EXECUTION = ("succeeded", "failed", "cancelled")


def execution_operation_id(tenant_id: UUID, execution_id: UUID) -> str:
    """Stable external operation identity for one execution (one reserved approval use)."""
    return hashlib.sha256(f"axiom-action|{tenant_id}|{execution_id}".encode()).hexdigest()


def perm(verb: str, effect: str) -> str:
    """Exact per-class permission (ACT-08): no hierarchy, so weaker classes never authorise stronger ones."""
    return f"action.{verb}:{effect.replace('.', '_')}"     # catalogue names allow no dot after the colon


def precondition_failures(case: dict, version: dict) -> list[str]:
    pre = version["preconditions"]
    failures = []
    if pre.get("case_open") and case["workflow"] == "closed":
        failures.append("case is closed")
    if "case_priority" in pre and case["priority"] != pre["case_priority"]:
        failures.append(f"case priority changed from {pre['case_priority']} to {case['priority']} (material change)")
    if str(case["scope_id"]) != str(version["scope_id"]):
        failures.append("case scope changed")
    if "plan_epoch" in pre and case["plan_epoch"] != pre["plan_epoch"]:
        failures.append("the remediation plan was withdrawn after this proposal (R7); the proposal is obsolete")
    return failures


def check_execution(conn: psycopg.Connection, ctx: TenantContext, execution_id: UUID) -> str | None:
    """Everything that must still hold immediately before the effect (ACT-03, A07, A08, ACT-10).

    Runs inside the effect gate's fenced transaction. Returns the reason to deny, or None.
    """
    authz = Authorizer(conn, ctx)
    e = conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()
    if e is None:
        return "execution not found"
    p = conn.execute("SELECT * FROM axiom.action_proposals WHERE id = %s FOR SHARE", (e["proposal_id"],)).fetchone()
    v = conn.execute("SELECT * FROM axiom.action_proposal_versions WHERE id = %s", (e["proposal_version_id"],)).fetchone()
    a = conn.execute("SELECT * FROM axiom.approvals WHERE id = %s FOR SHARE", (e["approval_id"],)).fetchone()
    now = authz.now()
    if p["status"] != "open":
        return f"proposal is {p['status']}"
    if p["current_version"] != v["version"]:
        return "the proposal was revised after approval; the approved version is no longer current"
    if v["payload_digest"] != a["payload_digest"] or v["payload_digest"] != e["payload_digest"]:
        return "payload digest mismatch"
    if v["expires_at"] <= now:
        return "proposal version expired"
    if a["status"] != "active" or a["decision"] != "approved":
        return f"approval is {a['status']}"
    if a["valid_until"] <= now:
        return "approval expired"
    if not authz.has(perm("approve", v["effect_class"]), v["scope_id"], principal_id=a["approver_principal_id"]):
        return f"approver no longer holds {perm('approve', v['effect_class'])} for this scope"
    if not authz.has(perm("execute", v["effect_class"]), v["scope_id"], principal_id=e["requested_by"]):
        return f"requester no longer holds {perm('execute', v['effect_class'])} for this scope"
    case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (v["case_id"],)).fetchone()
    failures = precondition_failures(case, v)
    if failures:
        return "; ".join(failures)
    connection = conn.execute("SELECT status FROM axiom.connections WHERE id = %s", (e["connection_id"],)).fetchone()
    if connection["status"] != "active":
        return "connection is disabled"
    return None


class ActionService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer):
        self.conn, self.ctx, self.authz = conn, ctx, authz

    # ------------------------------------------------------------------ helpers
    def _case(self, case_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
        if row is None or not self.authz.has("case.read", row["scope_id"]):
            raise NotFound("case not found", code="case_not_found")
        return row

    def _proposal(self, proposal_id: UUID, *, lock: bool = False) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.action_proposals WHERE id = %s" + (" FOR UPDATE" if lock else ""),
                                (proposal_id,)).fetchone()
        if row is None or not self.authz.has("proposal.read", row["scope_id"]):
            raise NotFound("proposal not found", code="proposal_not_found")
        return row

    def _version(self, proposal_id: UUID, version: int) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.action_proposal_versions WHERE proposal_id = %s AND version = %s",
                                (proposal_id, version)).fetchone()
        if row is None:
            raise NotFound("proposal version not found", code="proposal_version_not_found")
        return row

    def _connection(self, connection_id: UUID, cls, case_scope: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.connections WHERE id = %s", (connection_id,)).fetchone()
        if row is None:
            raise NotFound("connection not found", code="connection_not_found")
        if row["adapter"] not in cls.adapters or row["adapter_kind"] != "workflow":
            raise ValidationFailed(f"connection adapter {row['adapter']} cannot execute {cls.name}")
        if row["status"] != "active":
            raise ValidationFailed("connection is disabled")
        if row["scope_id"] not in self.authz.scope_lineage(case_scope):
            raise ValidationFailed("connection scope does not cover the case")
        return row

    def _expiry(self, cls, expires_at: datetime, now: datetime) -> datetime:
        if expires_at.tzinfo is None or expires_at <= now:
            raise ValidationFailed("expires_at must be a future, timezone-aware time")
        if expires_at > now + timedelta(days=cls.max_proposal_days):
            raise ValidationFailed(f"proposals for {cls.name} expire within {cls.max_proposal_days} days")
        return expires_at

    def _insert_version(self, proposal: dict, version: int, case: dict, connection: dict, payload: dict,
                        rollback: str | None, verification: str, expires_at: datetime) -> dict:
        if not verification.strip():
            raise ValidationFailed("verification criteria are required")
        target = payload.get("project_key") or connection["config"].get("repo") or connection["config"].get("table")
        resources = [{"type": "case", "id": str(case["id"])},
                     {"type": "connection", "id": str(connection["id"]), "adapter": connection["adapter"],
                      "target": target}]
        preconditions = {"case_open": True, "case_priority": case["priority"], "plan_epoch": case["plan_epoch"]}
        return self.conn.execute(
            """INSERT INTO axiom.action_proposal_versions(tenant_id, id, proposal_id, version, effect_class, scope_id,
                   case_id, connection_id, resources, canonical_payload, preconditions, rollback_guidance,
                   verification_criteria, owner_principal_id, expires_at, payload_digest, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '', %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), proposal["id"], version, proposal["effect_class"], proposal["scope_id"],
             case["id"], connection["id"], Jsonb(resources), Jsonb(payload), Jsonb(preconditions), rollback,
             verification, self.ctx.principal_id, expires_at, self.ctx.principal_id)).fetchone()

    # ---------------------------------------------------------------- proposals
    def propose(self, *, case_id: UUID, effect: str, connection_id: UUID, payload: dict, verification_criteria: str,
                expires_at: datetime, rollback_guidance: str | None = None) -> dict:
        cls = effect_class(effect)
        case = self._case(case_id)
        authority = self.authz.require(perm("propose", cls.name), case["scope_id"])
        if case["workflow"] == "closed":
            raise Conflict("cannot propose actions for a closed case", code="case_closed")
        connection = self._connection(connection_id, cls, case["scope_id"])
        canonical = canonical_ticket_payload(payload, connection["adapter"])
        expires_at = self._expiry(cls, expires_at, self.authz.now())
        proposal = self.conn.execute(
            """INSERT INTO axiom.action_proposals(tenant_id, id, case_id, effect_class, scope_id, status, current_version,
                   created_by) VALUES (%s, %s, %s, %s, %s, 'open', 1, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), case_id, cls.name, case["scope_id"], self.ctx.principal_id)).fetchone()
        version = self._insert_version(proposal, 1, case, connection, canonical, rollback_guidance,
                                       verification_criteria, expires_at)
        audit.record(self.conn, self.ctx, action="action.proposed", resource_type="action_proposal",
                     resource_id=proposal["id"], detail={"version": 1, "digest": version["payload_digest"],
                                                         "effect_class": cls.name, "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="action.proposed", aggregate_type="action_proposal",
                       aggregate_id=proposal["id"], payload={"version": 1, "case_id": str(case_id)})
        return {**proposal, "version": version}

    def revise(self, proposal_id: UUID, expected_version: int, *, payload: dict, verification_criteria: str,
               expires_at: datetime, rollback_guidance: str | None = None) -> dict:
        proposal = self._proposal(proposal_id, lock=True)
        cls = effect_class(proposal["effect_class"])
        authority = self.authz.require(perm("propose", proposal["effect_class"]), proposal["scope_id"])
        if proposal["status"] != "open":
            raise Conflict(f"proposal is {proposal['status']}", code="proposal_not_open")
        if proposal["current_version"] != expected_version:
            raise Conflict("proposal was revised meanwhile", code="stale_version",
                           details={"current_version": proposal["current_version"]})
        previous = self._version(proposal_id, expected_version)
        case = self._case(proposal["case_id"])
        connection = self._connection(previous["connection_id"], cls, case["scope_id"])
        canonical = canonical_ticket_payload(payload, connection["adapter"])
        expires_at = self._expiry(cls, expires_at, self.authz.now())
        new_number = expected_version + 1
        self.conn.execute("""UPDATE axiom.action_proposals SET current_version = %s, record_version = record_version + 1
                              WHERE id = %s""", (new_number, proposal_id))
        version = self._insert_version(proposal, new_number, case, connection, canonical, rollback_guidance,
                                       verification_criteria, expires_at)
        audit.record(self.conn, self.ctx, action="action.revised", resource_type="action_proposal",
                     resource_id=proposal_id, detail={"version": new_number, "digest": version["payload_digest"],
                                                      "previous_digest": previous["payload_digest"],
                                                      "authority": authority.as_json()})
        return {**proposal, "current_version": new_number, "version": version}

    def withdraw(self, proposal_id: UUID, reason: str) -> dict:
        proposal = self._proposal(proposal_id, lock=True)
        authority = self.authz.require(perm("propose", proposal["effect_class"]), proposal["scope_id"])
        if proposal["status"] != "open":
            raise Conflict(f"proposal is {proposal['status']}", code="proposal_not_open")
        if not reason.strip():
            raise ValidationFailed("a reason is required")
        row = self.conn.execute("""UPDATE axiom.action_proposals SET status = 'withdrawn',
                                          record_version = record_version + 1 WHERE id = %s RETURNING *""",
                                (proposal_id,)).fetchone()
        audit.record(self.conn, self.ctx, action="action.withdrawn", resource_type="action_proposal",
                     resource_id=proposal_id, detail={"reason": reason, "authority": authority.as_json()})
        return row

    def get(self, proposal_id: UUID) -> dict:
        proposal = self._proposal(proposal_id)
        versions = list(self.conn.execute(
            "SELECT * FROM axiom.action_proposal_versions WHERE proposal_id = %s ORDER BY version", (proposal_id,)))
        approvals = list(self.conn.execute(
            """SELECT id, proposal_version_id, payload_digest, decision, approver_principal_id, valid_until, max_uses,
                      uses_reserved, uses_released, status, revoked_at, revocation_reason, created_at
                 FROM axiom.approvals WHERE proposal_id = %s ORDER BY created_at""", (proposal_id,)))
        executions = list(self.conn.execute(
            "SELECT * FROM axiom.action_executions WHERE proposal_id = %s ORDER BY created_at", (proposal_id,)))
        return {**proposal, "versions": versions, "approvals": approvals, "executions": executions}

    # ---------------------------------------------------------------- approvals
    def decide(self, proposal_id: UUID, version_number: int, *, decision: str, rationale: str,
               valid_until: datetime | None = None, max_uses: int = 1) -> dict:
        if decision not in ("approved", "rejected"):
            raise ValidationFailed("decision must be approved or rejected")
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        proposal = self._proposal(proposal_id, lock=True)
        cls = effect_class(proposal["effect_class"])
        authority = self.authz.require(perm("approve", proposal["effect_class"]), proposal["scope_id"])
        if proposal["status"] != "open":
            raise Conflict(f"proposal is {proposal['status']}", code="proposal_not_open")
        if proposal["current_version"] != version_number:
            raise Conflict("only the current version can be decided", code="stale_version",
                           details={"current_version": proposal["current_version"]})
        version = self._version(proposal_id, version_number)
        authors = {r["created_by"] for r in self.conn.execute(
            "SELECT created_by FROM axiom.action_proposal_versions WHERE proposal_id = %s", (proposal_id,))}
        if self.ctx.principal_id in authors | {proposal["created_by"]}:
            raise Forbidden("proposers cannot decide their own proposals", code="separation_of_duties")
        now = self.authz.now()
        if version["expires_at"] <= now:
            raise Conflict("proposal version expired", code="proposal_expired")
        valid_until = valid_until or version["expires_at"]
        if valid_until.tzinfo is None or valid_until <= now or valid_until > version["expires_at"]:
            raise ValidationFailed("valid_until must be in the future and not after the proposal expiry")
        if not 1 <= max_uses <= cls.max_uses_limit:
            raise ValidationFailed(f"max_uses for {cls.name} is 1 to {cls.max_uses_limit}")
        binding_scope = self.conn.execute(
            "SELECT scope_id FROM axiom.role_bindings WHERE id = ANY(%s) ORDER BY created_at LIMIT 1",
            (list(authority.binding_ids),)).fetchone()["scope_id"]
        row = self.conn.execute(
            """INSERT INTO axiom.approvals(tenant_id, id, proposal_id, proposal_version_id, payload_digest, decision,
                   approver_principal_id, authorised_scope_id, authority_snapshot, rationale, valid_until, max_uses,
                   status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), proposal_id, version["id"], version["payload_digest"], decision,
             self.ctx.principal_id, binding_scope, Jsonb(authority.as_json()), rationale, valid_until,
             max_uses if decision == "approved" else 1, "active" if decision == "approved" else "rejected")
        ).fetchone()
        audit.record(self.conn, self.ctx, action=f"action.{decision}", resource_type="approval",
                     resource_id=row["id"], detail={"proposal_id": str(proposal_id), "version": version_number,
                                                    "digest": version["payload_digest"], "max_uses": max_uses,
                                                    "valid_until": valid_until.isoformat(),
                                                    "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic=f"action.{decision}", aggregate_type="action_proposal",
                       aggregate_id=proposal_id, payload={"approval_id": str(row["id"]), "version": version_number})
        return row

    def revoke_approval(self, approval_id: UUID, reason: str) -> dict:
        if not reason.strip():
            raise ValidationFailed("a reason is required")
        approval = self.conn.execute("SELECT * FROM axiom.approvals WHERE id = %s", (approval_id,)).fetchone()
        if approval is None:
            raise NotFound("approval not found", code="approval_not_found")
        proposal = self._proposal(approval["proposal_id"], lock=True)
        approval = self.conn.execute("SELECT * FROM axiom.approvals WHERE id = %s FOR UPDATE", (approval_id,)).fetchone()
        if approval["approver_principal_id"] == self.ctx.principal_id:
            authority = self.authz.require("proposal.read", proposal["scope_id"])
        else:
            authority = self.authz.require(perm("approve", proposal["effect_class"]), proposal["scope_id"])
        if approval["status"] != "active":
            raise Conflict(f"approval is {approval['status']}", code="approval_not_active")
        row = self.conn.execute(
            """UPDATE axiom.approvals SET status = 'revoked', revoked_at = clock_timestamp(), revoked_by = %s,
                      revocation_reason = %s, record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (self.ctx.principal_id, reason, approval_id)).fetchone()
        audit.record(self.conn, self.ctx, action="approval.revoked", resource_type="approval", resource_id=approval_id,
                     detail={"reason": reason, "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="approval.revoked", aggregate_type="action_proposal",
                       aggregate_id=approval["proposal_id"], payload={"approval_id": str(approval_id)})
        return row

    # --------------------------------------------------------------- executions
    def request_execution(self, proposal_id: UUID, version_number: int, approval_id: UUID) -> dict:
        # lock order: proposal, then approval (Design S 7: consistent locking of accounting rows)
        proposal = self._proposal(proposal_id, lock=True)
        authority = self.authz.require(perm("execute", proposal["effect_class"]), proposal["scope_id"])
        approval = self.conn.execute("SELECT * FROM axiom.approvals WHERE id = %s AND proposal_id = %s FOR UPDATE",
                                     (approval_id, proposal_id)).fetchone()
        if approval is None:
            raise NotFound("approval not found", code="approval_not_found")
        version = self._version(proposal_id, version_number)
        if approval["proposal_version_id"] != version["id"] or approval["payload_digest"] != version["payload_digest"]:
            raise Conflict("approval does not match this proposal version", code="approval_mismatch")
        if proposal["status"] != "open" or proposal["current_version"] != version_number:
            raise Conflict("only the current version of an open proposal can be executed", code="stale_version")
        now = self.authz.now()
        if approval["status"] != "active" or approval["decision"] != "approved":
            raise Conflict(f"approval is {approval['status']}", code="approval_not_active")
        if approval["valid_until"] <= now or version["expires_at"] <= now:
            raise Conflict("approval or proposal expired", code="approval_expired")
        if approval["uses_reserved"] - approval["uses_released"] >= approval["max_uses"]:
            raise Conflict("approval has no remaining uses", code="approval_exhausted")
        denial = None
        if not self.authz.has(perm("approve", proposal["effect_class"]), proposal["scope_id"],
                              principal_id=approval["approver_principal_id"]):
            denial = f"approver no longer holds {perm('approve', proposal['effect_class'])} for this scope"
        case = self._case(proposal["case_id"])
        denial = denial or "; ".join(precondition_failures(case, version)) or None
        if denial:
            raise Conflict(denial, code="precondition_failed")
        execution_id = uuid.uuid4()
        approval = self.conn.execute(
            """UPDATE axiom.approvals SET uses_reserved = uses_reserved + 1, record_version = record_version + 1
                WHERE id = %s RETURNING *""", (approval_id,)).fetchone()
        self.conn.execute(
            """INSERT INTO axiom.action_executions(tenant_id, id, proposal_id, proposal_version_id, payload_digest,
                   approval_id, connection_id, requested_by, external_operation_id, state)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'prepared')""",
            (self.ctx.tenant_id, execution_id, proposal_id, version["id"], version["payload_digest"], approval_id,
             version["connection_id"], self.ctx.principal_id, execution_operation_id(self.ctx.tenant_id, execution_id)))
        self.conn.execute(
            """INSERT INTO axiom.approval_reservations(tenant_id, id, approval_id, execution_id, use_number, status)
               VALUES (%s, %s, %s, %s, %s, 'reserved')""",
            (self.ctx.tenant_id, uuid.uuid4(), approval_id, execution_id, approval["uses_reserved"]))
        job = enqueue(self.conn, self.ctx, kind=EXECUTE_KIND, version=1, payload={"execution_id": str(execution_id)},
                      dedupe_key=f"execution:{execution_id}", aggregate=("action_execution", execution_id),
                      max_attempts=8, max_claims=20)
        row = self.conn.execute(
            """UPDATE axiom.action_executions SET job_id = %s, updated_at = clock_timestamp(),
                      record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (job["id"], execution_id)).fetchone()
        audit.record(self.conn, self.ctx, action="action.execution_requested", resource_type="action_execution",
                     resource_id=execution_id, detail={"proposal_id": str(proposal_id), "version": version_number,
                                                       "approval_id": str(approval_id),
                                                       "use_number": approval["uses_reserved"],
                                                       "authority": authority.as_json()})
        return row

    def get_execution(self, execution_id: UUID) -> dict:
        e = self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()
        if e is None:
            raise NotFound("execution not found", code="execution_not_found")
        self._proposal(e["proposal_id"])
        refs = list(self.conn.execute("SELECT * FROM axiom.external_references WHERE execution_id = %s", (execution_id,)))
        intent = self.conn.execute("SELECT state, attempts, external_ref, resolution, dedupe, lookup FROM "
                                   "axiom.effect_intents WHERE operation_key = %s",
                                   (e["external_operation_id"],)).fetchone()
        return {**e, "external_references": refs, "intent": intent}

    def cancel_execution(self, execution_id: UUID, reason: str) -> dict:
        """Request cancellation. A job no worker holds is settled now from the effect evidence
        (``settle_cancellation``); a running job is flagged and settled by its worker, at its next claim or final
        write. The result may be cancelled (use returned), succeeded (the effect is on record) or reconciling (the use
        stays reserved until an operator establishes the outcome)."""
        e = self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()
        if e is None:
            raise NotFound("execution not found", code="execution_not_found")
        proposal = self._proposal(e["proposal_id"])
        authority = self.authz.require(perm("execute", proposal["effect_class"]), proposal["scope_id"])
        # lock the job before the execution, the order the worker uses (job row, then execution, then intent)
        job = self.conn.execute("SELECT * FROM axiom.jobs WHERE id = %s FOR UPDATE", (e["job_id"],)).fetchone()
        e = self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s FOR UPDATE", (execution_id,)).fetchone()
        if e["state"] in TERMINAL_EXECUTION:
            raise Conflict(f"execution is {e['state']}", code="execution_finished")
        if job["state"] in ("queued", "waiting", "needs_operator", "running"):
            self.conn.execute("""UPDATE axiom.jobs SET cancel_requested = true, updated_at = clock_timestamp(),
                                        record_version = record_version + 1 WHERE id = %s""", (job["id"],))
            event(self.conn, self.ctx, job["id"], "cancel_requested", detail={"reason": reason})
        if job["state"] in ("queued", "waiting", "needs_operator"):
            settle_cancelled_job(self.conn, self.ctx, job["id"],
                                 settle_cancellation(self.conn, self.ctx, execution_id, job, reason=reason))
        audit.record(self.conn, self.ctx, action="action.execution_cancel_requested", resource_type="action_execution",
                     resource_id=execution_id, detail={"reason": reason, "authority": authority.as_json()})
        return self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()

    def reconcile(self, execution_id: UUID, *, resolution: str, rationale: str, external_ref: str | None = None
                  ) -> dict:
        """Operator decision for an execution whose outcome could not be established (ACT-06).

        Never changes the approval: 'not_applied' re-runs the *same* reserved use through the full re-check (or, when
        cancellation was requested, lets the cancellation settle from that evidence: cancelled, use returned);
        'abandon' ends it with the use consumed (the effect may exist)."""
        e = self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()
        if e is None:
            raise NotFound("execution not found", code="execution_not_found")
        proposal = self._proposal(e["proposal_id"])
        from ...jobs import JobOperations
        # resolve_effect locks the job row first; the execution row is locked after it (the worker's order)
        row = JobOperations(self.conn, self.ctx, self.authz, permission="action.reconcile",
                            scope_id=proposal["scope_id"], aggregate="action_execution").resolve_effect(
            e["job_id"], resolution=resolution, rationale=rationale, external_ref=external_ref)
        recorded = self.conn.execute(
            """SELECT external_ref FROM axiom.effect_intents WHERE operation_key = %s
                 AND state IN ('succeeded', 'reconciled') AND external_ref IS NOT NULL""",
            (e["external_operation_id"],)).fetchone()
        if resolution == "adopt" and recorded and recorded["external_ref"] != external_ref:
            # raising rolls back the whole decision, including the job change above
            raise Conflict(f"the recorded effect is {recorded['external_ref']}, not {external_ref}",
                           code="effect_evidence_conflict")
        locked = self.conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s FOR UPDATE",
                                   (execution_id,)).fetchone()
        if resolution == "adopt" and row["state"] == "succeeded":
            # No open intent was left to re-run, so the gate will not verify this reference. Finishing the execution
            # from it is allowed only when it is the success the gate itself recorded and that record is not
            # contested; an operator-typed reference with nothing recorded to agree with is refused (rolls back).
            problem = (locked["outcome_detail"] or {}).get("problem")
            if recorded is None or problem:
                raise Conflict(
                    ("the recorded object failed verification: " + problem) if problem else
                    "no recorded effect to verify this reference against; abandon the execution (the use stays "
                    "consumed) or resolve not_applied if nothing was sent", code="effect_evidence_missing")
        if resolution == "abandon":
            # Abandoning records that the operator could not establish the outcome, not that nothing happened: the
            # use is never returned, so the approval cannot authorize a second attempt at an effect that may exist.
            # An operator who has established that nothing was sent cancels the execution and resolves not_applied.
            finish_execution(self.conn, self.ctx, execution_id, "failed", return_use=False,
                             detail={"abandoned_by_operator": True, "rationale": rationale,
                                     "external_effect": "unknown",
                                     "reservation": "consumed: an abandoned effect may exist, so its use is not "
                                                    "returned"})
        elif resolution == "adopt" and row["state"] == "succeeded":
            # A worker that lost its lease recorded the success but was not allowed to transition the execution:
            # the job is finished, so the execution is too, from the recorded (and here matching) reference.
            finish_execution(self.conn, self.ctx, execution_id, "succeeded", external_ref=external_ref,
                             how="adopted_by_operator", detail={"operator_resolution": resolution,
                                                                 "rationale": rationale})
        else:
            set_execution_state(self.conn, execution_id, "prepared" if resolution == "not_applied" else "reconciling",
                                {"operator_resolution": resolution, "rationale": rationale})
        return {"execution": self.get_execution(execution_id), "job": row}


# ------------------------------------------------------------------------------ execution state helpers
def effect_how(intent: dict | None, gate_how: str | None = None) -> str:
    """How a recorded external reference was obtained, for ``external_references.how``."""
    if gate_how in ("created", "adopted_by_lookup"):
        return gate_how
    resolution = (intent or {}).get("resolution") or ""
    if resolution.startswith("adopt:"):
        return "adopted_by_operator"
    if resolution in ("adopted by lookup", "provider reported the existing object"):
        return "adopted_by_lookup"
    return "created"


def effect_evidence(conn, e: dict) -> tuple[str, dict | None, str]:
    """What the durable records establish about one execution's external effect: ``(kind, intent, why)``.

    * ``succeeded``: an effect with an external reference is recorded (``succeeded`` or ``reconciled`` intent).
    * ``failed`` / ``abandoned``: the intent says so; the effect was rejected or an operator abandoned it.
    * ``never_began``: no dispatch began. Either no intent exists, or the intent is ``prepared`` and every dispatch
      the gate authorized is accounted for as not applied (``unaccounted_dispatches``); and the database can vouch
      that its effect records are complete (``restore_doubt``). The gate writes the intent, and marks it ``executing``
      with an ``effect_attempt`` event, in a transaction that commits before any request is sent, so these records
      are written ahead of every dispatch.
    * ``may_have_begun``: anything else, including an outcome that is merely unknown. The absence of a response is
      never treated as evidence that nothing happened.

    Locks the intent row (after the job and execution rows, the order the gate and the worker use)."""
    intent = conn.execute("SELECT * FROM axiom.effect_intents WHERE operation_key = %s FOR UPDATE",
                          (e["external_operation_id"],)).fetchone()
    if intent is not None:
        if intent["state"] in ("succeeded", "reconciled") and intent["external_ref"]:
            return "succeeded", intent, f"the effect {intent['external_ref']} is recorded"
        if intent["state"] in ("failed", "abandoned"):
            return intent["state"], intent, f"the effect intent is {intent['state']}"
        if intent["state"] != "prepared":
            return "may_have_begun", intent, (f"a dispatch was authorized (intent {intent['state']}) and its outcome "
                                              "has not been established")
    job = conn.execute("SELECT * FROM axiom.jobs WHERE id = %s", (e["job_id"],)).fetchone()
    doubt = restore_doubt(conn, job, intent)
    if doubt:
        return "may_have_begun", intent, f"this database cannot vouch for its effect records: {doubt}"
    open_attempts = unaccounted_dispatches(conn, e["job_id"])
    if open_attempts:
        return "may_have_begun", intent, (f"dispatches authorized under lease tokens {open_attempts} have no "
                                          "recorded outcome")
    if intent is None or intent["attempts"] == 0:
        return "never_began", intent, "no dispatch was authorized"
    return "never_began", intent, "every authorized dispatch was reported not applied"


def settle_cancellation(conn, ctx: TenantContext, execution_id: UUID, job: dict, *,
                        reason: str = "cancellation requested"):
    """Settle a requested cancellation from the effect evidence (``effect_evidence``), in the caller's transaction.
    Returns the job outcome for ``settle_cancelled_job``. Called by the worker that may write the job (at claim, or
    in the lease holder's final write) and by ``ActionService.cancel_execution`` for a job no worker holds.

    * never began: the execution is cancelled and its reservation released, in this one transaction;
    * a recorded success: the execution succeeds from that record (unverified), not cancelled;
    * a recorded failure or abandonment: the execution fails with the use consumed;
    * otherwise: the execution is put into reconciliation with the use still reserved, and the job is parked for an
      operator. The reservation keeps counting against the approval, so no fresh execution can reuse it."""
    e = conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s FOR UPDATE", (execution_id,)).fetchone()
    if e is None:
        return Fail("cancelled: execution not found")
    if e["state"] in TERMINAL_EXECUTION:
        if e["state"] == "succeeded":
            return Done({"execution_id": str(execution_id), "external_ref": e["external_ref"],
                         "already_finished": True})
        return Fail(f"cancelled: execution already {e['state']}")
    kind, intent, why = effect_evidence(conn, e)
    base = {"cancellation": reason, "evidence": why}
    problem = (e["outcome_detail"] or {}).get("problem")
    if kind == "succeeded" and problem:      # the recorded object failed verification: the record is contested
        kind, why = "may_have_begun", f"{why}, but it failed verification ({problem})"
    if kind == "succeeded":
        ref, how = intent["external_ref"], effect_how(intent)
        finish_execution(conn, ctx, execution_id, "succeeded", external_ref=ref, how=how, verified=False,
                         detail={**base, "settled_from": "recorded effect"})
        return Done({"execution_id": str(execution_id), "external_ref": ref, "how": how,
                     "cancellation_requested": True})
    if kind in ("failed", "abandoned"):
        finish_execution(conn, ctx, execution_id, "failed", detail={**base, "error": why})
        return Fail(f"cancelled: {why}")
    if kind == "never_began" and e["state"] != "reconciling":
        finish_execution(conn, ctx, execution_id, "cancelled", detail={**base, "external_effect": "none"})
        return Fail(f"cancelled before any dispatch: {why}")
    if kind == "never_began":
        why = f"the execution is under reconciliation ({why}); an operator decides it"
    held = ("held: the effect may exist, so the approval use stays reserved until an operator establishes the "
            "outcome (adopt, not_applied or abandon)")
    set_execution_state(conn, execution_id, "reconciling",
                        {**base, "evidence": why, "external_effect": "unknown", "reservation": held})
    earlier = f" Parked earlier: {job['operator_reason']}" if job.get("operator_reason") else ""
    return NeedsOperator(f"cancellation requested, but {why}. The approval use stays reserved.{earlier}")


def set_execution_state(conn, execution_id: UUID, state: str, detail: dict | None = None,
                        external_ref: str | None = None) -> dict | None:
    e = conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s FOR UPDATE", (execution_id,)).fetchone()
    if e["state"] in TERMINAL_EXECUTION or (e["state"] == state and not detail and not external_ref):
        return e
    return conn.execute(
        """UPDATE axiom.action_executions SET state = %s, external_ref = COALESCE(%s, external_ref),
                  outcome_detail = outcome_detail || %s, updated_at = clock_timestamp(),
                  record_version = record_version + 1 WHERE id = %s RETURNING *""",
        (state, external_ref, Jsonb(detail or {}), execution_id)).fetchone()


def finish_execution(conn, ctx: TenantContext, execution_id: UUID, state: str, *, external_ref: str | None = None,
                     how: str | None = None, verified: bool = False, detail: dict | None = None,
                     return_use: bool = True) -> None:
    """Finish an execution and settle its reservation in the same transaction. A cancelled or failed execution
    returns its use only when ``effect_evidence`` establishes that no dispatch began (and ``return_use``); otherwise
    the use is consumed."""
    e = conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s FOR UPDATE", (execution_id,)).fetchone()
    if e["state"] in TERMINAL_EXECUTION:
        return
    set_execution_state(conn, execution_id, state, detail, external_ref)
    reservation = conn.execute("SELECT * FROM axiom.approval_reservations WHERE execution_id = %s FOR UPDATE",
                               (execution_id,)).fetchone()
    if reservation and reservation["status"] == "reserved":
        kind, _, why = effect_evidence(conn, e) if state in ("cancelled", "failed") else ("", None, "")
        if return_use and kind == "never_began":
            conn.execute("""UPDATE axiom.approval_reservations SET status = 'released', release_reason = %s,
                                   record_version = record_version + 1 WHERE id = %s""",
                         (f"execution {state}: {why}", reservation["id"]))
            conn.execute("""UPDATE axiom.approvals SET uses_released = uses_released + 1,
                                   record_version = record_version + 1 WHERE id = %s AND status = 'active'""",
                         (e["approval_id"],))
        else:
            conn.execute("""UPDATE axiom.approval_reservations SET status = 'consumed',
                                   record_version = record_version + 1 WHERE id = %s""", (reservation["id"],))
    if state == "succeeded":
        v = conn.execute("SELECT case_id FROM axiom.action_proposal_versions WHERE id = %s",
                         (e["proposal_version_id"],)).fetchone()
        conn.execute(
            """INSERT INTO axiom.external_references(tenant_id, id, execution_id, case_id, provider, connection_id,
                   external_id, verified, how)
               SELECT %s, %s, %s, %s, c.adapter, c.id, %s, %s, %s FROM axiom.connections c WHERE c.id = %s
               ON CONFLICT (tenant_id, execution_id) DO NOTHING""",
            (ctx.tenant_id, uuid.uuid4(), execution_id, v["case_id"], external_ref, verified, how or "created",
             e["connection_id"]))
    audit.record(conn, ctx, action=f"action.execution_{state}", resource_type="action_execution",
                 resource_id=execution_id, detail={"external_ref": external_ref, "how": how, **(detail or {})})
    outbox.enqueue(conn, ctx, topic=f"action.execution_{state}", aggregate_type="action_execution",
                   aggregate_id=execution_id, payload={"external_ref": external_ref})


__all__ = ["ActionService", "check_execution", "effect_evidence", "effect_how", "execution_operation_id",
           "finish_execution", "set_execution_state", "settle_cancellation", "EXECUTE_KIND"]

