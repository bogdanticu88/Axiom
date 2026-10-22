"""Investigation service: model routes, runs, cancellation, claim review and reads (ADR 0012)."""
from __future__ import annotations

import uuid
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .. import audit, outbox
from ..access import Authorizer
from ..db import TenantContext
from ..errors import Conflict, Forbidden, NotFound, ValidationFailed
from ..jobs import enqueue
from . import snapshots as snaps
from .tools import DEFAULT_GRANTS, validate_grants

RUN_KIND = "investigation.run"
TERMINAL = ("completed", "incomplete", "failed", "cancelled")
BUDGET_DEFAULTS = {"max_rounds": 4, "max_model_calls": 8, "max_tool_calls": 12, "max_input_tokens": 200_000,
                   "max_output_tokens": 32_000, "max_cost_micros": 5_000_000}
BUDGET_CAPS = {"max_rounds": 10, "max_model_calls": 30, "max_tool_calls": 50, "max_input_tokens": 2_000_000,
               "max_output_tokens": 200_000, "max_cost_micros": 100_000_000}


class InvestigationService:
    def __init__(self, conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer, *,
                 env: str = "development", model_destinations: frozenset[str] = frozenset(),
                 tool_destinations: frozenset[str] = frozenset()):
        self.conn, self.ctx, self.authz = conn, ctx, authz
        self.env, self.model_destinations, self.tool_destinations = env, model_destinations, tool_destinations

    def _root(self) -> UUID:
        return self.conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()["id"]

    def _case(self, case_id: UUID) -> dict:
        case = self.conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
        if case is None or not self.authz.has("case.read", case["scope_id"]):
            raise NotFound("case not found", code="case_not_found")
        return case

    # ------------------------------------------------------------------------------------------- routes
    def propose_route(self, *, name: str, provider: str, model: str, endpoint: str, region: str,
                      max_classification: str, rationale: str, credential_ref: str | None = None,
                      input_price_micros_per_mtok: int = 0, output_price_micros_per_mtok: int = 0,
                      timeout_seconds: int = 60, max_retries: int = 1, max_output_tokens: int = 4096) -> dict:
        authority = self.authz.require("model.configure", self._root())
        if provider == "deterministic_fake":
            if self.env == "production":
                raise ValidationFailed("the deterministic fake provider is not permitted in production")
        elif endpoint.rstrip("/") not in self.model_destinations:
            raise ValidationFailed(f"{endpoint} is not a registered model destination (AXIOM_MODEL_DESTINATIONS)")
        try:
            row = self.conn.execute(
                """INSERT INTO axiom.model_routes(tenant_id, id, name, provider, model, endpoint, region, max_classification,
                       credential_ref, input_price_micros_per_mtok, output_price_micros_per_mtok, timeout_seconds,
                       max_retries, max_output_tokens, status, rationale, proposed_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'proposed', %s, %s) RETURNING *""",
                (self.ctx.tenant_id, uuid.uuid4(), name, provider, model, endpoint.rstrip("/"), region,
                 max_classification, credential_ref, input_price_micros_per_mtok, output_price_micros_per_mtok,
                 timeout_seconds, max_retries, max_output_tokens, rationale, self.ctx.principal_id)).fetchone()
        except psycopg.errors.CheckViolation as exc:
            raise ValidationFailed(f"invalid model route: {exc.diag.constraint_name}") from exc
        except psycopg.errors.UniqueViolation as exc:
            raise Conflict("a route with this name exists", code="route_exists") from exc
        audit.record(self.conn, self.ctx, action="model_route.proposed", resource_type="model_route",
                     resource_id=row["id"], detail={"name": name, "provider": provider, "model": model,
                                                    "endpoint": row["endpoint"], "region": region,
                                                    "max_classification": max_classification,
                                                    "authority": authority.as_json()})
        return row

    def approve_route(self, route_id: UUID, *, rationale: str) -> dict:
        authority = self.authz.require("model.approve", self._root())
        r = self.conn.execute("SELECT * FROM axiom.model_routes WHERE id = %s FOR UPDATE", (route_id,)).fetchone()
        if r is None:
            raise NotFound("route not found", code="route_not_found")
        if r["status"] != "proposed":
            raise Conflict(f"route is {r['status']}", code="route_not_proposed")
        if r["proposed_by"] == self.ctx.principal_id:
            raise Forbidden("a route must be approved by someone other than its proposer", code="separation_of_duties")
        row = self.conn.execute(
            """UPDATE axiom.model_routes SET status = 'approved', approved_by = %s, approved_at = clock_timestamp(),
                   record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (self.ctx.principal_id, route_id)).fetchone()
        audit.record(self.conn, self.ctx, action="model_route.approved", resource_type="model_route",
                     resource_id=route_id, detail={"rationale": rationale, "authority": authority.as_json()})
        return row

    def disable_route(self, route_id: UUID, *, rationale: str) -> dict:
        authority = self.authz.require("model.configure", self._root())
        r = self.conn.execute("SELECT * FROM axiom.model_routes WHERE id = %s FOR UPDATE", (route_id,)).fetchone()
        if r is None:
            raise NotFound("route not found", code="route_not_found")
        if r["status"] == "disabled":
            return r
        row = self.conn.execute(
            """UPDATE axiom.model_routes SET status = 'disabled', disabled_by = %s, disabled_at = clock_timestamp(),
                   record_version = record_version + 1 WHERE id = %s RETURNING *""",
            (self.ctx.principal_id, route_id)).fetchone()
        audit.record(self.conn, self.ctx, action="model_route.disabled", resource_type="model_route",
                     resource_id=route_id, detail={"rationale": rationale, "authority": authority.as_json()})
        return row

    def list_routes(self) -> list[dict]:
        if not self.authz.has("model.configure", self._root()):
            self.authz.require("investigation.read", self._root())
        return list(self.conn.execute(
            """SELECT id, name, provider, model, endpoint, region, max_classification, status, timeout_seconds,
                      max_retries, max_output_tokens, proposed_by, approved_by, created_at
                 FROM axiom.model_routes ORDER BY created_at"""))

    # ------------------------------------------------------------------------------------------- runs
    def start(self, case_id: UUID, *, questions: list[str], route: str, tools: list[str] | None = None,
              budget: dict | None = None, deadline_seconds: int = 900, snapshot_id: UUID | None = None) -> dict:
        case = self._case(case_id)
        authority = self.authz.require("investigation.run", case["scope_id"])
        if case["workflow"] == "closed":
            raise Conflict("case is closed", code="case_closed")
        if not 1 <= len(questions) <= 10 or any(not q.strip() or len(q) > 500 for q in questions):
            raise ValidationFailed("between 1 and 10 questions of at most 500 characters")
        if not 30 <= deadline_seconds <= 3600:
            raise ValidationFailed("deadline must be between 30 and 3600 seconds")
        b = dict(BUDGET_DEFAULTS)
        for k, v in (budget or {}).items():
            if k not in BUDGET_CAPS:
                raise ValidationFailed(f"unknown budget field {k}")
            if not isinstance(v, int) or not 1 <= v <= BUDGET_CAPS[k]:
                raise ValidationFailed(f"{k} must be an integer between 1 and {BUDGET_CAPS[k]}")
            b[k] = v
        r = self.conn.execute("SELECT * FROM axiom.model_routes WHERE name = %s OR id::text = %s", (route, route)).fetchone()
        if r is None or r["status"] != "approved":
            raise Conflict("model route is not approved", code="route_not_approved")
        try:
            grants = validate_grants(list(tools if tools is not None else DEFAULT_GRANTS), self.tool_destinations)
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        if snapshot_id is None:
            snap = snaps.build_snapshot(self.conn, self.ctx, self.authz, case_id, purpose="investigation")
        else:
            snap = self.conn.execute("SELECT * FROM axiom.evidence_snapshots WHERE id = %s AND case_id = %s",
                                     (snapshot_id, case_id)).fetchone()
            if snap is None:
                raise NotFound("snapshot not found for this case", code="snapshot_not_found")
        binding = {k: r[k] for k in ("provider", "model", "endpoint", "region", "max_classification", "credential_ref",
                                     "input_price_micros_per_mtok", "output_price_micros_per_mtok", "timeout_seconds",
                                     "max_retries", "max_output_tokens")}
        binding["route_id"], binding["route_name"] = str(r["id"]), r["name"]
        limitations = []
        if snap["max_classification"] and snaps.CLASS_RANK[snap["max_classification"]] > \
                snaps.CLASS_RANK[r["max_classification"]]:
            limitations.append({"code": "content_withheld_by_classification",
                                "message": f"snapshot holds {snap['max_classification']} content; route allows "
                                           f"{r['max_classification']}; that content is withheld from the model"})
        run_id = uuid.uuid4()
        deadline = self.conn.execute("SELECT clock_timestamp() + make_interval(secs => %s) AS d",
                                     (deadline_seconds,)).fetchone()["d"]
        qs = [{"id": f"q{i}", "text": q.strip()} for i, q in enumerate(questions, 1)]
        row = self.conn.execute(
            """INSERT INTO axiom.investigation_runs(tenant_id, id, case_id, snapshot_id, route_id, route_binding, questions,
                   tool_grants, budget, deadline_at, status, limitations, requested_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'queued', %s, %s) RETURNING *""",
            (self.ctx.tenant_id, run_id, case_id, snap["id"], r["id"], Jsonb(binding), Jsonb(qs), Jsonb(grants),
             Jsonb(b), deadline, Jsonb(limitations), self.ctx.principal_id)).fetchone()
        job = enqueue(self.conn, self.ctx, kind=RUN_KIND, version=1, payload={"run_id": str(run_id)},
                      dedupe_key=f"investigation:{run_id}", max_attempts=5, max_claims=80)
        row = self.conn.execute("UPDATE axiom.investigation_runs SET job_id = %s, record_version = record_version + 1 "
                                "WHERE id = %s RETURNING *", (job["id"], run_id)).fetchone()
        audit.record(self.conn, self.ctx, action="investigation.requested", resource_type="investigation_run",
                     resource_id=run_id, detail={"case_id": str(case_id), "snapshot_id": str(snap["id"]),
                                                 "route": r["name"], "tools": [g["tool"] for g in grants],
                                                 "budget": b, "authority": authority.as_json()})
        return row

    def cancel(self, run_id: UUID, *, reason: str) -> dict:
        run = self._run(run_id)
        case = self._case(run["case_id"])
        authority = self.authz.require("investigation.cancel", case["scope_id"])
        if run["status"] in TERMINAL:
            raise Conflict(f"run is {run['status']}", code="run_finished")
        row = self.conn.execute(
            """UPDATE axiom.investigation_runs SET cancel_requested_at = COALESCE(cancel_requested_at, clock_timestamp()),
                   cancel_requested_by = COALESCE(cancel_requested_by, %s), record_version = record_version + 1
                WHERE id = %s RETURNING *""", (self.ctx.principal_id, run_id)).fetchone()
        audit.record(self.conn, self.ctx, action="investigation.cancel_requested", resource_type="investigation_run",
                     resource_id=run_id, detail={"reason": reason, "authority": authority.as_json()})
        return row

    def _run(self, run_id: UUID) -> dict:
        run = self.conn.execute("SELECT * FROM axiom.investigation_runs WHERE id = %s", (run_id,)).fetchone()
        if run is None:
            raise NotFound("investigation not found", code="investigation_not_found")
        case = self.conn.execute("SELECT scope_id FROM axiom.finding_cases WHERE id = %s", (run["case_id"],)).fetchone()
        if not self.authz.has("investigation.read", case["scope_id"]):
            raise NotFound("investigation not found", code="investigation_not_found")
        return run

    def get(self, run_id: UUID) -> dict:
        run = self._run(run_id)
        claims = list(self.conn.execute("SELECT * FROM axiom.investigation_claims WHERE run_id = %s ORDER BY seq",
                                        (run_id,)))
        refs = list(self.conn.execute(
            """SELECT r.* FROM axiom.claim_references r JOIN axiom.investigation_claims c ON c.id = r.claim_id
                WHERE c.run_id = %s ORDER BY r.member_key""", (run_id,)))
        reviews = list(self.conn.execute("SELECT * FROM axiom.claim_reviews WHERE run_id = %s ORDER BY created_at",
                                         (run_id,)))
        for c in claims:
            c["supporting"] = [r["member_key"] for r in refs if r["claim_id"] == c["id"] and r["relation"] == "supports"]
            c["contradicting"] = [r["member_key"] for r in refs if r["claim_id"] == c["id"]
                                  and r["relation"] == "contradicts"]
            c["reviews"] = [r for r in reviews if r["claim_id"] == c["id"]]
        steps = list(self.conn.execute(
            """SELECT seq, kind, name, destination, status, attempt, request_digest, response_digest, input_tokens,
                      output_tokens, cost_micros, latency_ms, error, started_at, ended_at, detail
                 FROM axiom.investigation_steps WHERE run_id = %s ORDER BY seq""", (run_id,)))
        binding = {k: v for k, v in run["route_binding"].items() if k != "credential_ref"}
        return {**run, "route_binding": binding, "claims": claims, "steps": steps}

    def list_for_case(self, case_id: UUID) -> list[dict]:
        case = self._case(case_id)
        self.authz.require("investigation.read", case["scope_id"])
        return list(self.conn.execute(
            """SELECT id, snapshot_id, status, outcome_reason, model_calls, tool_calls, input_tokens, output_tokens,
                      cost_micros, created_at, ended_at FROM axiom.investigation_runs WHERE case_id = %s
                ORDER BY created_at""", (case_id,)))

    def review_claim(self, claim_id: UUID, *, verdict: str, note: str, corrected_conclusion: str | None = None) -> dict:
        claim = self.conn.execute("SELECT * FROM axiom.investigation_claims WHERE id = %s", (claim_id,)).fetchone()
        if claim is None:
            raise NotFound("claim not found", code="claim_not_found")
        case = self._case(claim["case_id"])
        authority = self.authz.require("investigation.review", case["scope_id"])
        if verdict not in ("confirmed", "rejected", "corrected"):
            raise ValidationFailed("verdict must be confirmed, rejected or corrected")
        if (verdict == "corrected") != (corrected_conclusion is not None):
            raise ValidationFailed("a corrected verdict needs a corrected conclusion, and only it")
        if verdict == "confirmed" and claim["validation"] == "rejected":
            raise Conflict("a rejected claim cannot be confirmed; correct it instead", code="claim_rejected")
        row = self.conn.execute(
            """INSERT INTO axiom.claim_reviews(tenant_id, id, claim_id, run_id, verdict, corrected_conclusion, note, reviewer)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
            (self.ctx.tenant_id, uuid.uuid4(), claim_id, claim["run_id"], verdict, corrected_conclusion, note,
             self.ctx.principal_id)).fetchone()
        audit.record(self.conn, self.ctx, action="investigation.claim_reviewed", resource_type="investigation_claim",
                     resource_id=claim_id, detail={"verdict": verdict, "corrected_conclusion": corrected_conclusion,
                                                   "authority": authority.as_json()})
        return row


def finish(conn, ctx, run: dict, status: str, reason: str | None) -> dict:
    row = conn.execute(
        """UPDATE axiom.investigation_runs SET status = %s, outcome_reason = %s, ended_at = clock_timestamp(),
               started_at = COALESCE(started_at, clock_timestamp()), record_version = record_version + 1
            WHERE id = %s RETURNING *""", (status, reason, run["id"])).fetchone()
    audit.record(conn, ctx, action=f"investigation.{status}", resource_type="investigation_run", resource_id=run["id"],
                 detail={"reason": reason, "model_calls": row["model_calls"], "tool_calls": row["tool_calls"],
                         "input_tokens": row["input_tokens"], "output_tokens": row["output_tokens"],
                         "cost_micros": row["cost_micros"]})
    outbox.enqueue(conn, ctx, topic=f"investigation.{status}", aggregate_type="finding_case", aggregate_id=run["case_id"],
                   payload={"run_id": str(run["id"]), "reason": reason})
    return row

