"""Two-step risk acceptance: request, authorise or reject, renew, expire and reassess (RISK-01..03, A11, R9).

Policy (``RiskPolicy``) decides when independent authorisation is required. The thresholds are **defaults** pending
the business decision on approval thresholds (Specification S 17); they are recorded with every request so a later
policy change does not rewrite history.

* request: a principal with ``risk.request`` asks for acceptance of a case in review (or renewal of an active
  acceptance on a case it closed). The case version and priority at that moment are recorded.
* authorise: a principal with ``risk.accept`` and a delegation limit covering the priority and duration, who is
  not the case owner, and not the requester when independence is required. The case must not have changed since
  the request (optimistic version check), otherwise the request is stale and must be renewed with current facts.
* renew: an authorised renewal supersedes the active acceptance with a new one; the case stays closed and its
  closure keeps pointing at the original acceptance, which the expiry sweep follows through the renewal chain.
* reassess: the sweep notifies the accountable owner ``reassessment_notice_days`` before expiry (once), lapses
  undecided requests, and at expiry reopens the case (``acceptance_expiry``) and notifies the owner.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ... import audit, outbox
from ...access import Authorizer
from ...db import TenantContext
from ...errors import Conflict, Forbidden, NotFound, ValidationFailed
from .model import ClosureReason, Workflow
from .service import CaseService


@dataclass(frozen=True)
class RiskPolicy:
    independent_priorities: tuple[str, ...] = ("pending", "urgent", "high")   # pending is treated as urgent
    independent_over_days: int = 90
    max_days: int = 365
    request_lapse_days: int = 14
    reassessment_notice_days: int = 14

    def evaluate(self, priority: str, now: datetime, expires_at: datetime) -> tuple[bool, list[str]]:
        reasons = []
        if priority in self.independent_priorities:
            reasons.append(f"priority {priority} requires independent authorisation")
        if expires_at - now > timedelta(days=self.independent_over_days):
            reasons.append(f"duration over {self.independent_over_days} days requires independent authorisation")
        return bool(reasons), reasons


DEFAULT_POLICY = RiskPolicy()


class RiskService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer,
                 policy: RiskPolicy = DEFAULT_POLICY):
        self.conn, self.ctx, self.authz, self.policy = conn, ctx, authz, policy
        self.cases = CaseService(conn, ctx, authz)

    def _case(self, case_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s FOR UPDATE", (case_id,)).fetchone()
        if row is None or not self.authz.has("case.read", row["scope_id"]):
            raise NotFound("case not found", code="case_not_found")
        return row

    def _request(self, request_id: UUID) -> dict:
        row = self.conn.execute("SELECT * FROM axiom.risk_acceptance_requests WHERE id = %s FOR UPDATE",
                                (request_id,)).fetchone()
        if row is None or not self.authz.has("case.read", row["scope_id"]):
            raise NotFound("risk acceptance request not found", code="risk_request_not_found")
        return row

    def _expiry(self, expires_at: datetime, now: datetime) -> datetime:
        if expires_at.tzinfo is None or expires_at <= now:
            raise ValidationFailed("risk acceptance requires a future, timezone-aware expiry")
        if expires_at > now + timedelta(days=self.policy.max_days):
            raise ValidationFailed(f"risk acceptance is limited to {self.policy.max_days} days")
        return expires_at

    def _active_chain_acceptance(self, case: dict) -> dict | None:
        """The active acceptance whose renewal chain starts at the acceptance the current closure relies on."""
        closure = self.conn.execute("SELECT * FROM axiom.closure_records WHERE case_id = %s AND case_event_sequence = %s",
                                    (case["id"], case["record_version"])).fetchone()
        if closure is None or closure["risk_acceptance_id"] is None:
            return None
        current = self.conn.execute("SELECT * FROM axiom.risk_acceptances WHERE id = %s",
                                    (closure["risk_acceptance_id"],)).fetchone()
        while current is not None and current["status"] == "superseded":
            current = self.conn.execute("SELECT * FROM axiom.risk_acceptances WHERE renewal_of = %s",
                                        (current["id"],)).fetchone()
        return current if current is not None and current["status"] == "active" else None

    # ------------------------------------------------------------------- request
    def request(self, case_id: UUID, expected_version: int, *, expires_at: datetime, rationale: str,
                compensating_controls: str | None = None) -> dict:
        case = self._case(case_id)
        authority = self.authz.require("risk.request", case["scope_id"])
        now = self.authz.now()
        expires_at = self._expiry(expires_at, now)
        if case["record_version"] != expected_version:
            raise Conflict("case was changed meanwhile", code="stale_version")
        if case["workflow"] == Workflow.REVIEW:
            kind, renewal_of = "new", None
        elif case["workflow"] == Workflow.CLOSED:
            active = self._active_chain_acceptance(case)
            if active is None:
                raise Conflict("only a case closed by an active risk acceptance can be renewed",
                               code="no_active_acceptance")
            if expires_at <= active["expires_at"]:
                raise ValidationFailed("a renewal must extend the current expiry")
            kind, renewal_of = "renewal", active["id"]
        else:
            raise Conflict("risk acceptance is requested from review", code="invalid_state")
        pending = self.conn.execute("SELECT id FROM axiom.risk_acceptance_requests WHERE case_id = %s AND "
                                    "status = 'pending'", (case_id,)).fetchone()
        if pending:
            raise Conflict("a request for this case is already pending", code="request_pending",
                           details={"request_id": str(pending["id"])})
        independent, reasons = self.policy.evaluate(case["priority"], now, expires_at)
        row = self.conn.execute(
            """INSERT INTO axiom.risk_acceptance_requests(tenant_id, id, case_id, scope_id, requested_by, kind, renewal_of,
                   case_record_version, case_priority, rationale, compensating_controls, requested_expires_at,
                   independent_required, policy, status, lapses_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), case_id, case["scope_id"], self.ctx.principal_id, kind, renewal_of,
             case["record_version"], case["priority"], rationale, compensating_controls, expires_at, independent,
             Jsonb({**asdict(self.policy), "reasons": reasons}),
             min(expires_at, now + timedelta(days=self.policy.request_lapse_days)))).fetchone()
        audit.record(self.conn, self.ctx, action="risk_acceptance.requested", resource_type="risk_acceptance_request",
                     resource_id=row["id"], detail={"case_id": str(case_id), "kind": kind,
                                                    "independent_required": independent, "reasons": reasons,
                                                    "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="risk_acceptance.requested", aggregate_type="finding_case",
                       aggregate_id=case_id, payload={"request_id": str(row["id"]), "kind": kind})
        return row

    # ----------------------------------------------------------------- decisions
    def _authoriser_checks(self, req: dict, case: dict, now: datetime) -> tuple:
        authority = self.authz.require("risk.accept", case["scope_id"])
        if case["owner_principal_id"] == self.ctx.principal_id:
            raise Forbidden("the case owner cannot accept its risk", code="separation_of_duties")
        if req["independent_required"] and req["requested_by"] == self.ctx.principal_id:
            raise Forbidden("this acceptance needs authorisation by someone other than the requester",
                            code="independent_authorisation_required", details={"reasons": req["policy"]["reasons"]})
        if req["status"] != "pending":
            raise Conflict(f"request is {req['status']}", code="request_not_pending")
        if req["lapses_at"] <= now:
            raise Conflict("request lapsed; request again with current facts", code="request_lapsed")
        limit = self.cases._delegation_limit("risk.accept", {**case, "priority": req["case_priority"]}, now,
                                             req["requested_expires_at"])
        return authority, limit

    def authorise(self, request_id: UUID, *, rationale: str) -> dict:
        req = self._request(request_id)
        case = self._case(req["case_id"])
        now = self.authz.now()
        authority, limit = self._authoriser_checks(req, case, now)
        if case["record_version"] != req["case_record_version"]:
            raise Conflict("the case changed after the request; the request is stale", code="request_stale")
        acceptance_id = uuid.uuid4()
        if req["kind"] == "new":
            def dependents(decision_id, _seq):
                self.conn.execute(
                    """INSERT INTO axiom.risk_acceptances(tenant_id, id, case_id, owner_principal_id, decision_id,
                           delegation_limit_id, rationale, compensating_controls, starts_at, expires_at, status,
                           request_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s)""",
                    (self.ctx.tenant_id, acceptance_id, case["id"], self.ctx.principal_id, decision_id, limit["id"],
                     req["rationale"], req["compensating_controls"], now, req["requested_expires_at"], req["id"]))
                return {"risk_acceptance_id": str(acceptance_id), "request_id": str(req["id"])}
            result = self.cases._close(case, case["record_version"], ClosureReason.ACCEPTED_RISK, rationale, authority,
                                       disposition="accept_risk", risk_acceptance_id=acceptance_id,
                                       pre_dependents=dependents, decision_kind="risk_acceptance")
        else:
            old = self.conn.execute("SELECT * FROM axiom.risk_acceptances WHERE id = %s FOR UPDATE",
                                    (req["renewal_of"],)).fetchone()
            if old["status"] != "active" or old["expires_at"] <= now:
                raise Conflict("the acceptance being renewed is no longer active", code="no_active_acceptance")
            decision_id = uuid.uuid4()
            self.conn.execute(
                """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id,
                       authority, supersedes_decision_id) VALUES (%s, %s, %s, 'risk_acceptance', 'renewed', %s, %s, %s,
                       %s)""",
                (self.ctx.tenant_id, decision_id, case["id"], rationale, self.ctx.principal_id,
                 Jsonb(authority.as_json()), old["decision_id"]))
            self.conn.execute(
                """INSERT INTO axiom.risk_acceptances(tenant_id, id, case_id, owner_principal_id, decision_id,
                       delegation_limit_id, rationale, compensating_controls, starts_at, expires_at, status, request_id,
                       renewal_of) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s)""",
                (self.ctx.tenant_id, acceptance_id, case["id"], self.ctx.principal_id, decision_id, limit["id"],
                 req["rationale"], req["compensating_controls"], now, req["requested_expires_at"], req["id"],
                 old["id"]))
            self.conn.execute("""UPDATE axiom.risk_acceptances SET status = 'superseded', ended_at = clock_timestamp(),
                                        record_version = record_version + 1 WHERE id = %s""", (old["id"],))
            result = case
        self.conn.execute(
            """UPDATE axiom.risk_acceptance_requests SET status = 'authorised', decided_by = %s,
                      decided_at = clock_timestamp(), decision_rationale = %s, acceptance_id = %s,
                      record_version = record_version + 1 WHERE id = %s""",
            (self.ctx.principal_id, rationale, acceptance_id, request_id))
        audit.record(self.conn, self.ctx, action="risk_acceptance.authorised", resource_type="risk_acceptance",
                     resource_id=acceptance_id, detail={"request_id": str(request_id), "kind": req["kind"],
                                                        "delegation_limit_id": str(limit["id"]),
                                                        "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="risk_acceptance.authorised", aggregate_type="finding_case",
                       aggregate_id=case["id"], payload={"acceptance_id": str(acceptance_id), "kind": req["kind"],
                                                         "notify_principal_id": str(req["requested_by"])})
        return {"case": result, "acceptance_id": acceptance_id, "request_id": request_id}

    def reject(self, request_id: UUID, *, rationale: str) -> dict:
        if not rationale.strip():
            raise ValidationFailed("a rationale is required")
        req = self._request(request_id)
        authority = self.authz.require("risk.accept", req["scope_id"])
        if req["status"] != "pending":
            raise Conflict(f"request is {req['status']}", code="request_not_pending")
        row = self.conn.execute(
            """UPDATE axiom.risk_acceptance_requests SET status = 'rejected', decided_by = %s, decided_at = clock_timestamp(),
                      decision_rationale = %s, record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (self.ctx.principal_id, rationale, request_id)).fetchone()
        audit.record(self.conn, self.ctx, action="risk_acceptance.rejected", resource_type="risk_acceptance_request",
                     resource_id=request_id, detail={"rationale": rationale, "authority": authority.as_json()})
        outbox.enqueue(self.conn, self.ctx, topic="risk_acceptance.rejected", aggregate_type="finding_case",
                       aggregate_id=req["case_id"], payload={"request_id": str(request_id),
                                                             "notify_principal_id": str(req["requested_by"])})
        return row

    def withdraw(self, request_id: UUID, *, reason: str) -> dict:
        req = self._request(request_id)
        if req["requested_by"] != self.ctx.principal_id:
            raise Forbidden("only the requester can withdraw a request", code="not_requester")
        if req["status"] != "pending":
            raise Conflict(f"request is {req['status']}", code="request_not_pending")
        row = self.conn.execute(
            """UPDATE axiom.risk_acceptance_requests SET status = 'withdrawn', decided_at = clock_timestamp(),
                      decision_rationale = %s, record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (reason, request_id)).fetchone()
        audit.record(self.conn, self.ctx, action="risk_acceptance.withdrawn", resource_type="risk_acceptance_request",
                     resource_id=request_id, detail={"reason": reason})
        return row

    def accept_directly(self, case_id: UUID, expected_version: int, *, expires_at: datetime, rationale: str,
                        compensating_controls: str | None = None) -> dict:
        """Single-call acceptance, allowed only where policy permits self-authorisation (low impact, short)."""
        req = self.request(case_id, expected_version, expires_at=expires_at, rationale=rationale,
                           compensating_controls=compensating_controls)
        if req["independent_required"]:
            raise Forbidden("this acceptance needs a request and independent authorisation",
                            code="independent_authorisation_required", details={"reasons": req["policy"]["reasons"]})
        return self.authorise(req["id"], rationale=rationale)["case"]


def risk_sweep(conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer,
               policy: RiskPolicy = DEFAULT_POLICY) -> dict:
    """Lapse undecided requests and send reassessment notices (expiry itself: cases.service.expire_risk_acceptances)."""
    lapsed = [r["id"] for r in conn.execute(
        """UPDATE axiom.risk_acceptance_requests SET status = 'lapsed', decided_at = clock_timestamp(),
                  decision_rationale = 'not decided before it lapsed', record_version = record_version + 1
            WHERE status = 'pending' AND lapses_at <= clock_timestamp() RETURNING id""")]
    for request_id in lapsed:
        audit.record(conn, ctx, action="risk_acceptance.request_lapsed", resource_type="risk_acceptance_request",
                     resource_id=request_id)
    notices = []
    for a in conn.execute(
            """SELECT * FROM axiom.risk_acceptances WHERE status = 'active' AND reassessment_notified_at IS NULL
                 AND expires_at > clock_timestamp()
                 AND expires_at <= clock_timestamp() + make_interval(days => %s)
               FOR UPDATE SKIP LOCKED""", (policy.reassessment_notice_days,)).fetchall():
        conn.execute("""UPDATE axiom.risk_acceptances SET reassessment_notified_at = clock_timestamp(),
                               record_version = record_version + 1 WHERE id = %s""", (a["id"],))
        audit.record(conn, ctx, action="risk_acceptance.reassessment_due", resource_type="risk_acceptance",
                     resource_id=a["id"], detail={"expires_at": a["expires_at"].isoformat()})
        outbox.enqueue(conn, ctx, topic="risk_acceptance.reassessment_due", aggregate_type="risk_acceptance",
                       aggregate_id=a["id"], payload={"case_id": str(a["case_id"]),
                                                      "notify_principal_id": str(a["owner_principal_id"]),
                                                      "expires_at": a["expires_at"].isoformat()})
        notices.append(a["id"])
    return {"lapsed": lapsed, "reassessment_notices": notices}
