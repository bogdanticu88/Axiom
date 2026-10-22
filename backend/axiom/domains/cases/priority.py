"""Prioritisation by a versioned policy (Specification S 7, A14).

``apply`` derives a priority from explicit inputs: the highest source-reported severity among the case's active
occurrences and the highest asserted criticality of the affected assets at that moment. Missing inputs are substituted
by the policy's conservative bucket and **recorded as limitations** on the decision, so uncertainty stays visible.
The decision carries the policy version (or states that the built-in provisional default was used). ``override``
records a manual priority with a rationale. Neither changes the workflow state.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from uuid import UUID

from ...errors import Conflict, ValidationFailed
from ..policies.service import CRITICALITIES, PRIORITIES, SEVERITIES, current
from . import model
from .model import Workflow
from .service import CaseService, _Plan

_SEV_ALIASES = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
                "info": "info", "informational": "info", "negligible": "info", "note": "low", "warning": "medium",
                "error": "high"}


def _rank(order, value):
    return len(order) - order.index(value)


def priority_inputs(svc: CaseService, case_id: UUID) -> dict:
    occ = svc.conn.execute(
        """SELECT o.source_severity, av.asset_id FROM axiom.case_occurrence_links l
             JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
             JOIN axiom.asset_versions av ON av.id = o.asset_version_id
            WHERE l.case_id = %s AND l.unlinked_at IS NULL""", (case_id,)).fetchall()
    sev_known = [_SEV_ALIASES[s.lower()] for s in (r["source_severity"] or "" for r in occ)
                 if s and s.lower() in _SEV_ALIASES]
    assets = sorted({r["asset_id"] for r in occ}, key=str)
    crits = []
    for asset_id in assets:
        ctx = svc.conn.execute(
            """SELECT criticality, basis FROM axiom.business_context_versions WHERE asset_id = %s
                 AND effective_from <= clock_timestamp() ORDER BY effective_from DESC, recorded_at DESC LIMIT 1""",
            (asset_id,)).fetchone()
        if ctx and ctx["criticality"]:
            crits.append(ctx["criticality"])
    return {"occurrences": len(occ), "severities_known": len(sev_known), "assets": [str(a) for a in assets],
            "assets_with_criticality": len(crits),
            "severity": max(sev_known, key=lambda s: _rank(SEVERITIES, s)) if sev_known else None,
            "criticality": max(crits, key=lambda c: _rank(CRITICALITIES, c)) if crits else None}


def evaluate(definition: dict, policy_id, provisional: bool, inputs: dict) -> tuple[str, list[str], str, str]:
    """Pure policy evaluation: (priority, limitations, effective severity, effective criticality). Used by apply,
    by override expiry and by the impact preview, so all three give the same answer for the same inputs."""
    limitations = []
    severity, criticality = inputs["severity"], inputs["criticality"]
    if severity is None:
        severity = definition["unknown_severity"]
        limitations.append(f"no usable source severity; treated as {severity}")
    elif inputs["severities_known"] < inputs["occurrences"]:
        limitations.append(f"{inputs['occurrences'] - inputs['severities_known']} occurrence(s) without severity")
    if criticality is None:
        criticality = definition["unknown_criticality"]
        limitations.append(f"no asserted asset criticality; treated as {criticality}")
    elif inputs["assets_with_criticality"] < len(inputs["assets"]):
        limitations.append(f"{len(inputs['assets']) - inputs['assets_with_criticality']} asset(s) without criticality")
    if policy_id is None:
        limitations.append("built-in provisional default policy (no published priority policy)")
    elif provisional:
        limitations.append("policy version marked provisional")
    return definition["matrix"][severity][criticality], limitations, severity, criticality


def active_override(conn, case_id: UUID) -> dict | None:
    return conn.execute("SELECT * FROM axiom.priority_overrides WHERE case_id = %s AND ended_at IS NULL",
                        (case_id,)).fetchone()


def apply(svc: CaseService, case_id: UUID, expected_version: int, *, rationale: str,
          provenance: dict | None = None) -> dict:
    case = svc._load(case_id)
    model.check_expected_version(case["record_version"], expected_version)
    if case["workflow"] == Workflow.CLOSED:
        raise Conflict("closed cases are not reprioritised; reopen first", code="invalid_state")
    authority = svc.authz.require("priority.apply", case["scope_id"])
    ov = active_override(svc.conn, case_id)
    if ov is not None and provenance is None:
        raise Conflict(f"a manual override ({ov['priority']}) is in force until {ov['expires_at'].isoformat()}",
                       code="override_active")
    definition, policy_id, provisional = current(svc.conn, "priority")
    inputs = priority_inputs(svc, case_id)
    priority, limitations, severity, criticality = evaluate(definition, policy_id, provisional, inputs)
    if provenance:
        limitations.insert(0, provenance["note"])
    payload = {"priority_from": case["priority"], "priority_to": priority, "inputs": inputs,
               "effective_severity": severity, "effective_criticality": criticality,
               "policy_version_id": str(policy_id) if policy_id else None, "provisional": provisional}
    if provenance:
        payload["provenance"] = {k: v for k, v in provenance.items() if k != "note"}
    return svc._apply(case, expected_version, _Plan(
        to_workflow=Workflow(case["workflow"]), event_type="case.prioritised", decision_kind="prioritisation",
        decision_outcome=priority, rationale=rationale, limitations="; ".join(limitations) or None,
        authority=authority, changes={"priority": priority}, payload=payload, policy_version_id=policy_id))


MAX_OVERRIDE = timedelta(days=365)
DEFAULT_OVERRIDE = timedelta(days=90)       # D-PRIO-2 (provisional)


def override(svc: CaseService, case_id: UUID, expected_version: int, *, priority: str, rationale: str,
             expires_at: datetime | None = None) -> dict:
    """A recorded manual priority with an expiry (default 90 days, at most 365). When it expires, the case is
    re-prioritised by the policy (see ``expire_overrides``); the priority before the override is not restored."""
    if priority not in PRIORITIES:
        raise ValidationFailed(f"priority must be one of {PRIORITIES}")
    case = svc._load(case_id)
    model.check_expected_version(case["record_version"], expected_version)
    if case["workflow"] == Workflow.CLOSED:
        raise Conflict("closed cases are not reprioritised; reopen first", code="invalid_state")
    authority = svc.authz.require("override.propose", case["scope_id"])
    now = svc.authz.now()
    expires_at = expires_at or now + DEFAULT_OVERRIDE
    if expires_at.tzinfo is None or not (now < expires_at <= now + MAX_OVERRIDE):
        raise ValidationFailed("override expiry must be in the future and within 365 days")
    previous = active_override(svc.conn, case_id)
    override_id = uuid.uuid4()

    def dependents(decision_id, _seq):
        if previous is not None:
            svc.conn.execute("""UPDATE axiom.priority_overrides SET ended_at = clock_timestamp(), end_reason = 'superseded',
                                       ended_by_decision_id = %s, record_version = record_version + 1 WHERE id = %s""",
                             (decision_id, previous["id"]))
        svc.conn.execute(
            """INSERT INTO axiom.priority_overrides(tenant_id, id, case_id, decision_id, priority, priority_before,
                   expires_at, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (svc.ctx.tenant_id, override_id, case_id, decision_id, priority, case["priority"], expires_at,
             svc.ctx.principal_id))
        return {"override_id": str(override_id)}

    return svc._apply(case, expected_version, _Plan(
        to_workflow=Workflow(case["workflow"]), event_type="case.priority_overridden", decision_kind="priority_override",
        decision_outcome=priority, rationale=rationale, authority=authority, changes={"priority": priority},
        payload={"priority_from": case["priority"], "priority_to": priority, "manual": True,
                 "expires_at": expires_at.isoformat(),
                 "supersedes_override_id": str(previous["id"]) if previous else None},
        dependents=dependents))


EXPIRY_KIND = "cases.priority_override_expiry"


def expire_overrides(conn, ctx, *, now=None) -> dict:
    """End overrides whose expiry has passed and re-prioritise each open case from current inputs under the current
    policy, as the system principal (deterministic policy result, permission priority.apply). The decision records
    which override expired, when, and what it had set; closed cases only have the override ended."""
    from ...access import Authorizer
    now = now or conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    svc = CaseService(conn, ctx, Authorizer(conn, ctx))
    out = {"expired": 0, "reassessed": 0, "closed_cases": 0}
    for ov in conn.execute("""SELECT * FROM axiom.priority_overrides WHERE ended_at IS NULL AND expires_at <= %s
                               ORDER BY expires_at FOR UPDATE SKIP LOCKED""", (now,)).fetchall():
        case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (ov["case_id"],)).fetchone()
        out["expired"] += 1
        if case["workflow"] == Workflow.CLOSED:
            conn.execute("""UPDATE axiom.priority_overrides SET ended_at = clock_timestamp(), end_reason = 'case_closed',
                                   record_version = record_version + 1 WHERE id = %s""", (ov["id"],))
            out["closed_cases"] += 1
            continue
        note = (f"manual override {ov['id']} ({ov['priority']}, set by {ov['created_by']}) expired at "
                f"{ov['expires_at'].isoformat()}; priority re-derived from current inputs under the current policy, "
                f"not restored to the earlier {ov['priority_before']}")
        apply(svc, case["id"], case["record_version"], rationale="override expired: reassessment by policy",
              provenance={"note": note, "override_id": str(ov["id"]), "override_priority": ov["priority"],
                          "override_expired_at": ov["expires_at"].isoformat(),
                          "priority_before_override": ov["priority_before"]})
        decision = conn.execute("""SELECT id FROM axiom.decisions WHERE case_id = %s AND kind = 'prioritisation'
                                    ORDER BY recorded_at DESC, id DESC LIMIT 1""", (case["id"],)).fetchone()
        conn.execute("""UPDATE axiom.priority_overrides SET ended_at = clock_timestamp(), end_reason = 'expired',
                               ended_by_decision_id = %s, record_version = record_version + 1 WHERE id = %s""",
                     (decision["id"], ov["id"]))
        out["reassessed"] += 1
    return out


class OverrideExpiryHandler:
    kind = EXPIRY_KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc):
        from ...jobs import Done
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            return Done(expire_overrides(conn, jc.ctx))


# ------------------------------------------------------------------------------------------------ preview
def preview(conn, authz, *, definition: dict, policy_id=None, provisional: bool = True, limit: int = 2000,
            scopes=None) -> dict:
    """What a priority policy version would do to every open case the requester can read. Read-only: it writes no
    case, event, decision or override; only an audit record of the preview is written by the caller."""
    scopes = scopes if scopes is not None else authz.readable_scopes("case.read")
    rows = conn.execute(
        """WITH RECURSIVE covered(id) AS (SELECT id FROM axiom.scopes WHERE id = ANY(%s)
               UNION SELECT c.id FROM axiom.scopes c JOIN covered ON c.parent_id = covered.id)
           SELECT c.id, c.title, c.priority, c.workflow, c.scope_id,
                  (SELECT d.policy_version_id FROM axiom.decisions d WHERE d.case_id = c.id AND d.kind = 'prioritisation'
                    ORDER BY d.recorded_at DESC LIMIT 1) AS current_policy_version_id
             FROM axiom.finding_cases c WHERE c.workflow <> 'closed' AND c.scope_id IN (SELECT id FROM covered)
            ORDER BY c.created_at, c.id LIMIT %s""", (scopes, limit)).fetchall()
    class _Reader:            # priority_inputs only reads through .conn
        pass
    svc = _Reader()
    svc.conn = conn
    items, counts = [], {"cases": 0, "would_change": 0, "held_by_override": 0, "with_missing_inputs": 0}
    for r in rows:
        if not authz.has("case.read", r["scope_id"]):       # previewing never reveals a case the requester cannot read
            continue
        inputs = priority_inputs(svc, r["id"])
        new, limitations, sev, crit = evaluate(definition, policy_id, provisional, inputs)
        ov = active_override(conn, r["id"])
        missing = [lim for lim in limitations if lim.startswith(("no usable", "no asserted")) or "without" in lim]
        item = {"case_id": r["id"], "title": r["title"], "workflow": r["workflow"], "current_priority": r["priority"],
                "preview_priority": new, "changes": new != r["priority"], "effective_severity": sev,
                "effective_criticality": crit, "missing_inputs": missing,
                "current_policy_version_id": r["current_policy_version_id"],
                "override": ({"priority": ov["priority"], "expires_at": ov["expires_at"]} if ov else None)}
        if ov:
            item["note"] = "a manual override is in force; the preview applies only after it expires"
        counts["cases"] += 1
        counts["would_change"] += bool(item["changes"] and not ov)
        counts["held_by_override"] += bool(ov)
        counts["with_missing_inputs"] += bool(missing)
        items.append(item)
    return {"policy_version_id": policy_id, "provisional": provisional, "counts": counts, "items": items,
            "truncated": len(rows) == limit}
