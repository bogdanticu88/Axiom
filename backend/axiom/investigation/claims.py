"""Claim validation (INVS-04, INVS-05, A06; ADR 0012).

A model claim is stored with one of three validation results:

* ``rejected``: it cannot stand on the snapshot at all. Reasons include:
  * a reference that is not a member of the run's snapshot (fabricated, or from another snapshot, case or tenant);
  * an unavailable reference (unverified, above the route's classification, or unreadable by the requester);
  * a subject that is not in the snapshot;
  * a reference about a different vulnerability or asset (valid but irrelevant);
  * a reference whose recorded content contradicts what it is cited for (for example an "absent in complete scan"
    observation cited as support for presence);
  * a definite conclusion with no reference on the cited side.
* ``downgraded``: the references are acceptable, but the conclusion overreaches. The accepted conclusion becomes
  ``unknown``. This happens when:
  * a recorded contradiction is ignored;
  * only stale evidence is cited;
  * the attribute cannot be established from snapshot contents (exposure);
  * the most recent observation of the subject points the other way (for presence and absence claims).
* ``references_checked``: the references exist, are available, concern the stated subject and are consistent with the
  claimed attribute.

Even ``references_checked`` does **not** mean the statement follows from the references: the platform checks
references, subjects and recorded statuses, not reasoning. Every claim is stored with ``entailment = not_verified``,
and a human reviewer confirms, rejects or corrects it before an assessment may rely on the run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schema import Claim
from .snapshots import CLASS_RANK, EVIDENCE_READ

PRESENT = {"present"}
GONE = {"absent_in_complete_scan", "fixed_by_source", "suppressed_by_source"}
DIRECT_KINDS = {"occurrence", "occurrence_observation", "observation"}


@dataclass
class Result:
    validation: str
    accepted: str | None
    reasons: list[dict] = field(default_factory=list)
    refs: list[tuple[str, str]] = field(default_factory=list)       # (member_key, supports|contradicts)


def _status(m: dict) -> str | None:
    if m["kind"] == "occurrence_observation":
        return m["attributes"]["observed_status"]
    if m["kind"] == "observation":
        t = m["attributes"]["observation_type"]
        return {"finding_reported": "present", "finding_fixed_by_source": "fixed_by_source",
                "finding_suppressed_by_source": "suppressed_by_source"}.get(t)
    return None


def validate_claim(claim: Claim, members: dict[str, dict], contradictions: list[dict], *, route_max: str,
                   can_read: callable) -> Result:
    reasons: list[dict] = []
    keys = [("supports", k) for k in claim.supporting] + [("contradicts", k) for k in claim.contradicting]
    missing = [k for _, k in keys if k not in members]
    if missing:
        return Result("rejected", None, [{"code": "fabricated_reference", "member_keys": missing,
                                          "message": "not members of this run's snapshot"}])
    for rel, k in keys:
        m = members[k]
        if not m["available"]:
            reasons.append({"code": "reference_unavailable", "member_key": k, "message": "not verified or unavailable"})
        elif m["classification"] and (CLASS_RANK[m["classification"]] > CLASS_RANK[route_max]
                                      or not can_read(EVIDENCE_READ[m["classification"]])):
            reasons.append({"code": "reference_unavailable", "member_key": k,
                            "message": f"{m['classification']} content not available to this run"})
    if reasons:
        return Result("rejected", None, reasons)
    subj = claim.subject
    vulns = {m["attributes"].get("vulnerability_ref") for m in members.values() if m["kind"] == "occurrence"}
    assets = {m["ref_id"] for m in members.values() if m["kind"] == "asset"}
    if subj.vulnerability_ref and subj.vulnerability_ref not in vulns:
        return Result("rejected", None, [{"code": "subject_not_in_snapshot",
                                          "message": f"{subj.vulnerability_ref} is not in this snapshot"}])
    if subj.asset_id and str(subj.asset_id) not in {str(a) for a in assets}:
        return Result("rejected", None, [{"code": "subject_not_in_snapshot", "message": "asset is not in this snapshot"}])
    for rel, k in keys:
        a = members[k]["attributes"]
        if members[k]["kind"] in DIRECT_KINDS:
            if subj.vulnerability_ref and a.get("vulnerability_ref") != subj.vulnerability_ref:
                reasons.append({"code": "irrelevant_reference", "member_key": k,
                                "message": f"concerns {a.get('vulnerability_ref')}, not {subj.vulnerability_ref}"})
            elif subj.asset_id and a.get("asset_id") and str(a.get("asset_id")) != str(subj.asset_id):
                reasons.append({"code": "irrelevant_reference", "member_key": k, "message": "concerns another asset"})
        elif members[k]["kind"] in ("business_context", "asset_version") and subj.asset_id \
                and str(a.get("asset_id")) != str(subj.asset_id):
            reasons.append({"code": "irrelevant_reference", "member_key": k, "message": "concerns another asset"})
    if reasons:
        return Result("rejected", None, reasons)
    sup = [members[k] for k in claim.supporting]
    con = [members[k] for k in claim.contradicting]
    attr, concl = subj.attribute, claim.conclusion
    # attribute semantics: a cited record must say what it is cited for
    if attr in ("present_in_deployment", "absent_in_deployment"):
        pos, neg = (PRESENT, GONE) if attr == "present_in_deployment" else (GONE, PRESENT)
        for m in sup:
            if _status(m) in neg:
                reasons.append({"code": "reference_contradicts_claim", "member_key": m["member_key"],
                                "message": f"records {_status(m)}, cited as support"})
        for m in con:
            if _status(m) in pos:
                reasons.append({"code": "reference_contradicts_claim", "member_key": m["member_key"],
                                "message": f"records {_status(m)}, cited as contradiction"})
        direct_sup = [m for m in sup if _status(m) in pos]
        direct_con = [m for m in con if _status(m) in neg]
    elif attr == "severity_as_reported":
        direct_sup = [m for m in sup if m["kind"] in ("occurrence", "observation")]
        direct_con = [m for m in con if m["kind"] in ("occurrence", "observation")]
    elif attr == "business_context":
        direct_sup = [m for m in sup if m["kind"] == "business_context"]
        direct_con = [m for m in con if m["kind"] == "business_context"]
    elif attr == "fix_available":
        direct_sup = [m for m in sup if m["kind"] == "observation"
                      and (m["attributes"].get("normalised") or {}).get("fixed_version")]
        direct_con = [m for m in con if m["kind"] == "observation"]
    else:
        direct_sup = [m for m in sup if m["kind"] in DIRECT_KINDS]
        direct_con = [m for m in con if m["kind"] in DIRECT_KINDS]
    if reasons:
        return Result("rejected", None, reasons)
    if concl == "supported" and not direct_sup:
        return Result("rejected", None, [{"code": "conclusion_without_reference",
                                          "message": f"no cited record establishes {attr}"}])
    if concl == "contradicted" and not direct_con:
        return Result("rejected", None, [{"code": "conclusion_without_reference",
                                          "message": f"no cited record contradicts {attr}"}])
    refs = [("supports" if rel == "supports" else "contradicts", k) for rel, k in keys]
    accepted, downgrades = concl, []
    if concl != "unknown":
        cited = set(claim.supporting) | set(claim.contradicting)
        for c in contradictions:
            relevant = (c["kind"] == "presence_disagreement" and attr in ("present_in_deployment", "absent_in_deployment")
                        and (not subj.vulnerability_ref or c.get("vulnerability_ref") == subj.vulnerability_ref)) \
                or (c["kind"] == "severity_disagreement" and attr == "severity_as_reported") \
                or (c["kind"] == "context_disagreement" and attr == "business_context")
            if not relevant:
                continue
            other_side = con if concl == "supported" else sup
            if not other_side or not (set(c.get("member_keys", [])) & cited):
                downgrades.append({"code": "ignores_recorded_contradiction", "contradiction": c["kind"],
                                   "message": "the snapshot records a contradiction this claim does not address"})
        decisive = direct_sup if concl == "supported" else direct_con
        if decisive and all(m["freshness"] in ("stale", "unknown") for m in decisive
                            if m["freshness"] != "not_applicable") \
                and any(m["freshness"] != "not_applicable" for m in decisive):
            downgrades.append({"code": "stale_evidence_only", "message": "every decisive reference is stale or of "
                                                                         "unknown freshness"})
        if attr in ("present_in_deployment", "absent_in_deployment"):
            # the most recent observation of the subject decides which way the evidence currently points; a
            # conclusion against it is not accepted even when both sides are cited
            obs = [m for m in members.values() if m["kind"] == "occurrence_observation"
                   and m["attributes"].get("vulnerability_ref") == subj.vulnerability_ref
                   and (not subj.asset_id or str(m["attributes"].get("asset_id")) == str(subj.asset_id))]
            if obs:
                latest = max(obs, key=lambda m: m["attributes"].get("recorded_at") or "")
                says_present = _status(latest) in PRESENT
                claims_present = (attr == "present_in_deployment") == (concl == "supported")
                if says_present != claims_present:
                    downgrades.append({"code": "latest_observation_disagrees", "member_key": latest["member_key"],
                                       "message": f"the most recent observation records {_status(latest)}"})
        if attr == "exposure":
            downgrades.append({"code": "attribute_not_established",
                               "message": "exposure or exploitability cannot be established from scanner observations"})
    if downgrades:
        return Result("downgraded", "unknown", downgrades, refs)
    if concl == "unknown" and not claim.limitations:
        reasons.append({"code": "no_limitation_stated", "message": "unknown conclusion without a stated limitation"})
    return Result("references_checked", accepted, reasons, refs)
