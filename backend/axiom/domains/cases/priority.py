"""Prioritisation by a versioned policy (Specification S 7, A14).

``apply`` derives a priority from explicit inputs: the highest source-reported severity among the case's active
occurrences and the highest asserted criticality of the affected assets at that moment. Missing inputs are substituted
by the policy's conservative bucket and **recorded as limitations** on the decision, so uncertainty stays visible.
The decision carries the policy version (or states that the built-in provisional default was used). ``override``
records a manual priority with a rationale. Neither changes the workflow state.
"""
from __future__ import annotations

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


def apply(svc: CaseService, case_id: UUID, expected_version: int, *, rationale: str) -> dict:
    case = svc._load(case_id)
    model.check_expected_version(case["record_version"], expected_version)
    if case["workflow"] == Workflow.CLOSED:
        raise Conflict("closed cases are not reprioritised; reopen first", code="invalid_state")
    authority = svc.authz.require("priority.apply", case["scope_id"])
    definition, policy_id, provisional = current(svc.conn, "priority")
    inputs = priority_inputs(svc, case_id)
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
    priority = definition["matrix"][severity][criticality]
    payload = {"priority_from": case["priority"], "priority_to": priority, "inputs": inputs,
               "effective_severity": severity, "effective_criticality": criticality,
               "policy_version_id": str(policy_id) if policy_id else None, "provisional": provisional}
    return svc._apply(case, expected_version, _Plan(
        to_workflow=Workflow(case["workflow"]), event_type="case.prioritised", decision_kind="prioritisation",
        decision_outcome=priority, rationale=rationale, limitations="; ".join(limitations) or None,
        authority=authority, changes={"priority": priority}, payload=payload, policy_version_id=policy_id))


def override(svc: CaseService, case_id: UUID, expected_version: int, *, priority: str, rationale: str) -> dict:
    if priority not in PRIORITIES:
        raise ValidationFailed(f"priority must be one of {PRIORITIES}")
    case = svc._load(case_id)
    model.check_expected_version(case["record_version"], expected_version)
    if case["workflow"] == Workflow.CLOSED:
        raise Conflict("closed cases are not reprioritised; reopen first", code="invalid_state")
    authority = svc.authz.require("override.propose", case["scope_id"])
    return svc._apply(case, expected_version, _Plan(
        to_workflow=Workflow(case["workflow"]), event_type="case.priority_overridden", decision_kind="priority_override",
        decision_outcome=priority, rationale=rationale, authority=authority, changes={"priority": priority},
        payload={"priority_from": case["priority"], "priority_to": priority, "manual": True}))
