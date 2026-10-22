"""Deterministic claim checks (INVS-04, INVS-05, A06; ADR 0012).

**What these checks are.** They are record-level, deterministic rules over a frozen evidence snapshot. They check:

1. **Reference existence and membership.** Every cited key must be a member of the run's own snapshot. A snapshot
   belongs to one case in one tenant, so this also enforces tenant, case and scope membership.
2. **Availability.** A cited member must be verified, within the model route's classification limit, and readable
   by the requester at its classification.
3. **Subject matching.** The claim's subject (vulnerability, asset, optionally deployment) must exist in the
   snapshot, and every cited occurrence or observation must carry the **same** vulnerability identifier, asset and
   (when the subject names one) deployment. This is a comparison of identifiers. It is **not** a judgement of
   semantic relevance.
4. **Recorded-status consistency** for structured attributes:
   * presence and absence: the cited observation's recorded status must point the way it is cited;
   * reported severity: a cited occurrence or observation;
   * fix available: an observation with a fixed version;
   * business context: a context record for the asset.

   A definite conclusion needs at least one such record on the cited side.
5. **Freshness.** If every decisive reference is stale or of unknown freshness, the conclusion is downgraded.
6. **Structured contradiction rules**, using the contradiction records frozen in the snapshot:
   * a definite claim that cites only one side of a recorded contradiction is downgraded;
   * if the snapshot's ordering is ``undetermined`` (scan times missing, tied, or from different sources), any
     definite presence or absence conclusion is downgraded and the contradiction stays open for a person;
   * if the ordering is defensible (``by_scan_time``), a conclusion against the latest status is downgraded.

   Scan time comes from the source; import or recording time never decides.
7. **Deployment.** When the subject asset has several deployments in the snapshot, a presence or absence claim must
   name the deployment, or it is downgraded.
8. **Unsupported attributes.** Exposure or exploitability cannot be established from scanner records and is
   downgraded.

**What these checks are not.** They do not read the claim's statement text, so they do not decide whether the
statement follows from the references (entailment), whether a reference is meaningfully relevant beyond identifier
equality, or whether the reasoning is sound. A claim can pass every check and still be wrong. Every claim is stored
with ``entailment = not_verified``, and a human reviewer must confirm, reject or correct it before an assessment may
rely on the run.

Results:
* ``rejected``: no accepted conclusion; the references are not stored as links.
* ``downgraded``: the accepted conclusion is ``unknown``, with reasons.
* ``references_checked``: the proposed conclusion is accepted *as a candidate* for human review.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schema import Claim
from .snapshots import CLASS_RANK, EVIDENCE_READ

PRESENT = {"present"}
GONE = {"absent_in_complete_scan", "fixed_by_source", "suppressed_by_source"}
DIRECT_KINDS = {"occurrence", "occurrence_observation", "observation"}
PRESENCE_ATTRS = ("present_in_deployment", "absent_in_deployment")


@dataclass
class Result:
    validation: str
    accepted: str | None
    reasons: list[dict] = field(default_factory=list)
    refs: list[tuple[str, str]] = field(default_factory=list)       # (relation, member_key)


def _status(m: dict) -> str | None:
    if m["kind"] == "occurrence_observation":
        return m["attributes"]["observed_status"]
    if m["kind"] == "observation":
        return {"finding_reported": "present", "finding_fixed_by_source": "fixed_by_source",
                "finding_suppressed_by_source": "suppressed_by_source"}.get(m["attributes"]["observation_type"])
    return None


def _deployment(m: dict) -> str | None:
    a = m["attributes"]
    return str(a.get("asset_version_id")) if a.get("asset_version_id") else None


def validate_claim(claim: Claim, members: dict[str, dict], contradictions: list[dict], *, route_max: str,
                   can_read: callable) -> Result:
    keys = [("supports", k) for k in claim.supporting] + [("contradicts", k) for k in claim.contradicting]
    # 1. existence and membership
    missing = [k for _, k in keys if k not in members]
    if missing:
        return Result("rejected", None, [{"code": "fabricated_reference", "member_keys": missing,
                                          "message": "not members of this run's snapshot"}])
    # 2. availability
    reasons: list[dict] = []
    for _, k in keys:
        m = members[k]
        if not m["available"]:
            reasons.append({"code": "reference_unavailable", "member_key": k, "message": "not verified or unavailable"})
        elif m["classification"] and (CLASS_RANK[m["classification"]] > CLASS_RANK[route_max]
                                      or not can_read(EVIDENCE_READ[m["classification"]])):
            reasons.append({"code": "reference_unavailable", "member_key": k,
                            "message": f"{m['classification']} content not available to this run"})
    if reasons:
        return Result("rejected", None, reasons)
    # 3. subject matching (identifier equality only)
    subj = claim.subject
    occs = [m for m in members.values() if m["kind"] == "occurrence"
            and (not subj.vulnerability_ref or m["attributes"].get("vulnerability_ref") == subj.vulnerability_ref)
            and (not subj.asset_id or str(m["attributes"].get("asset_id")) == str(subj.asset_id))]
    if subj.vulnerability_ref and not occs:
        return Result("rejected", None, [{"code": "subject_not_in_snapshot",
                                          "message": f"{subj.vulnerability_ref} on this asset is not in this snapshot"}])
    assets = {str(m["ref_id"]) for m in members.values() if m["kind"] == "asset"}
    if subj.asset_id and str(subj.asset_id) not in assets:
        return Result("rejected", None, [{"code": "subject_not_in_snapshot", "message": "asset is not in this snapshot"}])
    if subj.asset_version_id:
        occs = [m for m in occs if _deployment(m) == str(subj.asset_version_id)]
        if not occs:
            return Result("rejected", None, [{"code": "subject_not_in_snapshot",
                                              "message": "that deployment is not affected in this snapshot"}])
    for _, k in keys:
        m = members[k]
        a = m["attributes"]
        if m["kind"] in DIRECT_KINDS:
            if subj.vulnerability_ref and a.get("vulnerability_ref") != subj.vulnerability_ref:
                reasons.append({"code": "subject_mismatch", "member_key": k,
                                "message": f"records {a.get('vulnerability_ref')}, the subject is {subj.vulnerability_ref}"})
            elif subj.asset_id and a.get("asset_id") and str(a.get("asset_id")) != str(subj.asset_id):
                reasons.append({"code": "subject_mismatch", "member_key": k, "message": "records another asset"})
            elif subj.asset_version_id and _deployment(m) and _deployment(m) != str(subj.asset_version_id):
                reasons.append({"code": "subject_mismatch", "member_key": k, "message": "records another deployment"})
        elif m["kind"] in ("business_context", "asset_version") and subj.asset_id \
                and str(a.get("asset_id")) != str(subj.asset_id):
            reasons.append({"code": "subject_mismatch", "member_key": k, "message": "records another asset"})
        elif m["kind"] == "asset_version" and subj.asset_version_id and str(m["ref_id"]) != str(subj.asset_version_id):
            reasons.append({"code": "subject_mismatch", "member_key": k, "message": "another deployment"})
    if reasons:
        return Result("rejected", None, reasons)
    # 4. recorded-status consistency for structured attributes
    sup = [members[k] for k in claim.supporting]
    con = [members[k] for k in claim.contradicting]
    attr, concl = subj.attribute, claim.conclusion
    if attr in PRESENCE_ATTRS:
        pos, neg = (PRESENT, GONE) if attr == "present_in_deployment" else (GONE, PRESENT)
        for m in sup:
            if _status(m) in neg:
                reasons.append({"code": "status_conflicts_with_citation", "member_key": m["member_key"],
                                "message": f"records {_status(m)}, cited as support"})
        for m in con:
            if _status(m) in pos:
                reasons.append({"code": "status_conflicts_with_citation", "member_key": m["member_key"],
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
                                          "message": f"no cited record has a status or field that establishes {attr}"}])
    if concl == "contradicted" and not direct_con:
        return Result("rejected", None, [{"code": "conclusion_without_reference",
                                          "message": f"no cited record has a status or field that contradicts {attr}"}])
    refs = [(rel, k) for rel, k in keys]
    downgrades: list[dict] = []
    if concl != "unknown":
        cited = set(claim.supporting) | set(claim.contradicting)
        occ_ids = {str(m["ref_id"]) for m in occs}
        # 7. deployment must be named when several are affected
        if attr in PRESENCE_ATTRS and not subj.asset_version_id and len({_deployment(m) for m in occs}) > 1:
            downgrades.append({"code": "deployment_unspecified",
                               "message": "several deployments of this asset are affected; name one"})
        # 6. structured contradiction rules
        for c in contradictions:
            if c["kind"] == "presence_disagreement" and attr in PRESENCE_ATTRS and c.get("occurrence_id") in occ_ids:
                other_side = con if concl == "supported" else sup
                if not other_side or not (set(c.get("member_keys", [])) & cited):
                    downgrades.append({"code": "ignores_recorded_contradiction", "contradiction": c["kind"],
                                       "message": "the snapshot records a contradiction this claim does not cite"})
                if c.get("ordering") != "by_scan_time":
                    downgrades.append({"code": "unresolved_contradiction", "contradiction": c["kind"],
                                       "message": "no defensible ordering: " + c.get("ordering_reason", "unknown")})
                else:
                    latest_present = c["latest_status"] in PRESENT
                    claims_present = (attr == "present_in_deployment") == (concl == "supported")
                    if latest_present != claims_present:
                        downgrades.append({"code": "latest_observation_disagrees", "contradiction": c["kind"],
                                           "message": f"the latest scan ({c.get('latest_scan_time')}) records "
                                                      f"{c['latest_status']}"})
            elif (c["kind"] == "severity_disagreement" and attr == "severity_as_reported") \
                    or (c["kind"] == "context_disagreement" and attr == "business_context"):
                other_side = con if concl == "supported" else sup
                if not other_side or not (set(c.get("member_keys", [])) & cited):
                    downgrades.append({"code": "ignores_recorded_contradiction", "contradiction": c["kind"],
                                       "message": "the snapshot records a contradiction this claim does not cite"})
        # 5. freshness
        decisive = direct_sup if concl == "supported" else direct_con
        timed = [m for m in decisive if m["freshness"] != "not_applicable"]
        if timed and all(m["freshness"] in ("stale", "unknown") for m in timed):
            downgrades.append({"code": "stale_evidence_only",
                               "message": "every decisive reference is stale or of unknown freshness"})
        # 8. attributes scanner records cannot establish
        if attr == "exposure":
            downgrades.append({"code": "attribute_not_established",
                               "message": "exposure or exploitability cannot be established from scanner records"})
    if downgrades:
        return Result("downgraded", "unknown", downgrades, refs)
    notes = []
    if concl == "unknown" and not claim.limitations:
        notes.append({"code": "no_limitation_stated", "message": "unknown conclusion without a stated limitation"})
    return Result("references_checked", concl, notes, refs)
