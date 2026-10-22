"""Frozen evidence snapshots (INVS-01; ADR 0012).

A snapshot records, for one case at one instant, exactly which records an assessment or investigation may rely on:

* every active occurrence linked to the case, its asset version (deployment digest) and asset;
* every observation of each occurrence by every run up to the snapshot time (present, fixed by source, suppressed,
  absent in a complete scan), with the observation version digest, collection time and the run's coverage;
* the runs themselves: adapter, declared scope or subject, coverage and completion time, and **freshness** against
  the freshness policy in force at the snapshot time;
* business-context versions for the affected assets;
* evidence objects: the raw reports behind the observations and evidence cited by earlier decisions on the case.

It also records what is **contradictory** (for example present in one scan and absent in a later complete scan;
sources disagreeing on severity; user and source-tag context disagreeing) and what is **missing** (no complete
scan, stale sources, no business context, no severity, unverified evidence). Nothing is resolved or dropped.

Members carry a frozen copy of the attributes used, so a snapshot keeps its meaning even if later records are added.
Snapshots and members are append-only; new evidence produces a new snapshot and a new assessment, never an edit.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from .. import audit
from ..access import Authorizer
from ..db import TenantContext
from ..errors import NotFound, ValidationFailed

CLASS_RANK = {"internal": 1, "confidential": 2, "restricted": 3}
KIND_ORDER = ["occurrence", "asset", "asset_version", "occurrence_observation", "observation", "ingestion_run",
              "business_context", "evidence_object"]
MAX_SOURCE_TEXT = 2000           # bounded copy of untrusted source text per observation
EVIDENCE_READ = {"internal": "evidence.read:internal", "confidential": "evidence.read:confidential",
                 "restricted": "evidence.read:restricted"}
EVIDENCE_META = {"internal": "evidence.metadata:internal", "confidential": "evidence.metadata:confidential",
                 "restricted": "evidence.metadata:restricted"}


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


def _iso(t):
    return t.isoformat() if isinstance(t, datetime) else t


def _bounded(value, limit=MAX_SOURCE_TEXT):
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"...[truncated {len(value) - limit} chars]"
    return value


def _freshness_policy(conn, as_of):
    from ..domains.policies.service import DEFAULTS
    row = conn.execute("""SELECT * FROM axiom.policy_versions WHERE kind = 'freshness' AND published_at <= %s
                           ORDER BY published_at DESC LIMIT 1""", (as_of,)).fetchone()
    return (row["definition"], row["id"]) if row else (DEFAULTS["freshness"], None)


def build_snapshot(conn: psycopg.Connection, ctx: TenantContext, authz: Authorizer, case_id: UUID, *,
                   purpose: str = "investigation") -> dict:
    case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
    if case is None or not authz.has("case.read", case["scope_id"]):
        raise NotFound("case not found", code="case_not_found")
    authority = authz.require("snapshot.create", case["scope_id"])
    if purpose not in ("investigation", "assessment"):
        raise ValidationFailed("purpose must be investigation or assessment")
    conn.execute("SET LOCAL TimeZone = 'UTC'")          # serialised times must not depend on the session
    as_of = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    policy, policy_id = _freshness_policy(conn, as_of)
    ages = policy["max_age_hours"]
    raw: list[tuple[str, UUID, dict]] = []          # (kind, ref_id, member fields)
    seen: set[tuple[str, UUID]] = set()

    def add(kind, ref_id, **fields):
        if (kind, ref_id) not in seen:
            seen.add((kind, ref_id))
            raw.append((kind, ref_id, fields))

    def run_fresh(run) -> str:
        if run is None or run["finished_at"] is None or run["status"] != "completed":
            return "unknown"
        age_h = (as_of - run["finished_at"]).total_seconds() / 3600
        return "fresh" if age_h <= ages.get(run["adapter"], ages["default"]) else "stale"

    occurrences = list(conn.execute(
        """SELECT o.*, l.linked_at FROM axiom.case_occurrence_links l JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
            WHERE l.case_id = %s AND l.linked_at <= %s AND (l.unlinked_at IS NULL OR l.unlinked_at > %s)
            ORDER BY o.created_at, o.id""", (case_id, as_of, as_of)))
    runs: dict[UUID, dict] = {}
    gaps, contradictions = [], []
    assets: dict[UUID, dict] = {}
    for occ in occurrences:
        av = conn.execute("SELECT * FROM axiom.asset_versions WHERE id = %s", (occ["asset_version_id"],)).fetchone()
        asset = conn.execute("SELECT * FROM axiom.assets WHERE id = %s", (av["asset_id"],)).fetchone()
        assets[asset["id"]] = asset
        add("occurrence", occ["id"], freshness="not_applicable", available=True, attributes={
            "source_system": occ["source_system"], "source_finding_id": occ["source_finding_id"],
            "vulnerability_ref": occ["vulnerability_ref"], "component_locator": occ["component_locator"],
            "source_severity": occ["source_severity"], "asset_id": str(asset["id"]),
            "asset_version_id": str(av["id"])})
        add("asset", asset["id"], freshness="not_applicable", available=True, attributes={
            "asset_kind": asset["asset_kind"], "display_name": asset["display_name"],
            "lifecycle_status": asset["lifecycle_status"]})
        add("asset_version", av["id"], ref_digest=av["deployment_digest"], collected_at=av["observed_at"],
            freshness="not_applicable", available=True, attributes={
                "asset_id": str(asset["id"]), "deployment_digest": av["deployment_digest"],
                "version_label": av["version_label"], "observed_at": _iso(av["observed_at"])})
        if not occ["source_severity"]:
            gaps.append({"kind": "missing_severity", "occurrence_id": str(occ["id"]),
                         "description": "the source reported no severity"})
        statuses = []
        for oo in conn.execute(
                """SELECT oo.*, ob.observation_digest, ob.collected_at, ob.raw_evidence_id, ob.raw_locator,
                          ob.observation_type, ob.normalised, ob.source_fields, ob.source_time AS ob_source_time
                     FROM axiom.occurrence_observations oo LEFT JOIN axiom.observations ob ON ob.id = oo.observation_id
                    WHERE oo.occurrence_id = %s AND oo.recorded_at <= %s ORDER BY oo.recorded_at, oo.run_id""",
                (occ["id"], as_of)):
            run = runs.get(oo["run_id"]) or conn.execute(
                "SELECT * FROM axiom.ingestion_runs WHERE id = %s", (oo["run_id"],)).fetchone()
            runs[run["id"]] = run
            fresh = run_fresh(run)
            ref = (oo["run_id"], oo["occurrence_id"])
            add("occurrence_observation", uuid.uuid5(uuid.NAMESPACE_URL, f"oo:{ref[0]}:{ref[1]}"),
                collected_at=oo["collected_at"] or oo["recorded_at"], freshness=fresh, available=True, attributes={
                    "occurrence_id": str(occ["id"]), "run_id": str(run["id"]),
                    "observation_id": str(oo["observation_id"]) if oo["observation_id"] else None,
                    "observed_status": oo["observed_status"], "vulnerability_ref": occ["vulnerability_ref"],
                    "asset_id": str(asset["id"]), "run_coverage": run["coverage"],
                    "run_finished_at": _iso(run["finished_at"]), "recorded_at": _iso(oo["recorded_at"])})
            statuses.append((oo["recorded_at"], oo["observed_status"], run))
            if oo["observation_id"]:
                ev = conn.execute("SELECT classification, status FROM axiom.evidence_objects WHERE id = %s",
                                  (oo["raw_evidence_id"],)).fetchone()
                sf = oo["source_fields"] or {}
                add("observation", oo["observation_id"], ref_digest=oo["observation_digest"],
                    classification=ev["classification"] if ev else None, collected_at=oo["collected_at"],
                    freshness=fresh, available=bool(ev and ev["status"] == "verified"), attributes={
                        "observation_type": oo["observation_type"], "run_id": str(run["id"]),
                        "raw_evidence_id": str(oo["raw_evidence_id"]), "raw_locator": oo["raw_locator"],
                        "vulnerability_ref": occ["vulnerability_ref"], "asset_id": str(asset["id"]),
                        "normalised": oo["normalised"],
                        # untrusted source text, bounded; it is data and never instructions
                        "source_text": {k: _bounded(sf.get(k)) for k in ("Title", "Description", "title",
                                                                          "description", "message") if sf.get(k)}})
        _occurrence_contradictions(occ, statuses, contradictions)
        latest_complete = [s for s in statuses if s[2]["coverage"] == "complete" and s[2]["status"] == "completed"]
        if not latest_complete:
            gaps.append({"kind": "no_complete_scan", "occurrence_id": str(occ["id"]),
                         "description": "no run with complete coverage has observed this occurrence"})
        elif run_fresh(latest_complete[-1][2]) != "fresh":
            gaps.append({"kind": "stale_complete_scan", "occurrence_id": str(occ["id"]),
                         "description": "the latest complete scan is older than the freshness policy allows"})
    if not occurrences:
        gaps.append({"kind": "no_occurrences", "description": "the case has no active linked occurrence"})
    sev = {o["source_severity"] for o in occurrences if o["source_severity"]}
    if len(sev) > 1:
        contradictions.append({"kind": "severity_disagreement", "occurrence_ids": sorted(str(o["id"]) for o in occurrences),
                               "description": f"sources report different severities: {sorted(sev)}"})
    for run in runs.values():
        add("ingestion_run", run["id"], collected_at=run["finished_at"], freshness=run_fresh(run), available=True,
            attributes={"adapter": run["adapter"], "source_kind": run["source_kind"], "status": run["status"],
                        "coverage": run["coverage"], "coverage_reason": _bounded(run["coverage_reason"], 500),
                        "declared_scope": run["declared_scope"], "declared_subject": run["declared_subject"],
                        "connection_id": str(run["connection_id"]) if run["connection_id"] else None,
                        "finished_at": _iso(run["finished_at"])})
        if run["raw_evidence_id"]:
            _add_evidence(conn, add, run["raw_evidence_id"], "raw report of an ingestion run")
    for asset_id in assets:
        versions = list(conn.execute(
            """SELECT * FROM axiom.business_context_versions WHERE asset_id = %s AND recorded_at <= %s
                 AND effective_from <= %s ORDER BY effective_from, recorded_at""", (asset_id, as_of, as_of)))
        if not versions:
            gaps.append({"kind": "no_business_context", "asset_id": str(asset_id),
                         "description": "no owner, criticality or environment recorded for this asset"})
        for v in versions:
            add("business_context", v["id"], collected_at=v["recorded_at"], freshness="not_applicable", available=True,
                attributes={"asset_id": str(asset_id), "basis": v["basis"], "owner_ref": v["owner_ref"],
                            "criticality": v["criticality"], "environment": v["environment"],
                            "effective_from": _iso(v["effective_from"])})
        by_basis = {}
        for v in versions:
            by_basis[v["basis"]] = v
        if len(by_basis) > 1:
            fields = [f for f in ("criticality", "owner_ref", "environment")
                      if len({b[f] for b in by_basis.values() if b[f] is not None}) > 1]
            if fields:
                contradictions.append({"kind": "context_disagreement", "asset_id": str(asset_id), "fields": fields,
                                       "description": "user and source assertions disagree"})
        if versions and not any(v["criticality"] for v in versions):
            gaps.append({"kind": "no_criticality", "asset_id": str(asset_id),
                         "description": "no criticality asserted for this asset"})
    for row in conn.execute(
            """SELECT DISTINCT de.evidence_object_id FROM axiom.decision_evidence de JOIN axiom.decisions d
                   ON d.id = de.decision_id WHERE d.case_id = %s AND d.recorded_at <= %s""", (case_id, as_of)):
        _add_evidence(conn, add, row["evidence_object_id"], "cited by an earlier decision on this case")
    digests = {}
    for (k, ref, f) in raw:
        if k == "asset_version":
            digests.setdefault(f["attributes"]["asset_id"], set()).add(f["attributes"]["deployment_digest"])
    for asset_id, ds in digests.items():
        if len(ds) > 1:
            contradictions.append({"kind": "multiple_deployment_versions", "asset_id": asset_id,
                                   "description": f"{len(ds)} different deployment versions are affected"})
    for (k, ref, f) in raw:
        if k == "evidence_object" and not f["available"]:
            gaps.append({"kind": "unverified_evidence", "evidence_id": str(ref),
                         "description": "evidence is not verified and cannot support a conclusion"})

    raw.sort(key=lambda r: (KIND_ORDER.index(r[0]), str(r[1])))
    members = []
    for i, (kind, ref_id, f) in enumerate(raw, 1):
        members.append({"member_key": f"M{i:03d}", "kind": kind, "ref_id": str(ref_id),
                        "ref_digest": f.get("ref_digest"), "classification": f.get("classification"),
                        "collected_at": _iso(f.get("collected_at")), "freshness": f["freshness"],
                        "available": f["available"], "attributes": f["attributes"]})
    key_of = {(m["kind"], m["ref_id"]): m["member_key"] for m in members}
    _attach_member_keys(contradictions, gaps, members, key_of)
    classes = [m["classification"] for m in members if m["classification"]]
    max_class = max(classes, key=CLASS_RANK.get) if classes else None
    snapshot_id = uuid.uuid4()
    body = {"case_id": str(case_id), "as_of": _iso(as_of), "freshness_policy_version_id": policy_id,
            "members": members, "contradictions": contradictions, "gaps": gaps}
    digest = hashlib.sha256(canonical(body)).hexdigest()
    row = conn.execute(
        """INSERT INTO axiom.evidence_snapshots(tenant_id, id, case_id, scope_id, as_of, purpose,
               freshness_policy_version_id, member_count, max_classification, contradictions, gaps, digest, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
        (ctx.tenant_id, snapshot_id, case_id, case["scope_id"], as_of, purpose, policy_id, len(members), max_class,
         Jsonb(contradictions), Jsonb(gaps), digest, ctx.principal_id)).fetchone()
    with conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO axiom.evidence_snapshot_members(tenant_id, snapshot_id, member_key, kind, ref_id, ref_digest,
                   classification, collected_at, freshness, available, attributes)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            [(ctx.tenant_id, snapshot_id, m["member_key"], m["kind"], m["ref_id"], m["ref_digest"], m["classification"],
              m["collected_at"], m["freshness"], m["available"], Jsonb(m["attributes"])) for m in members])
    audit.record(conn, ctx, action="evidence_snapshot.created", resource_type="evidence_snapshot",
                 resource_id=snapshot_id, detail={"case_id": str(case_id), "digest": digest, "members": len(members),
                                                  "contradictions": len(contradictions), "gaps": len(gaps),
                                                  "authority": authority.as_json()})
    return row


def _add_evidence(conn, add, evidence_id, why):
    ev = conn.execute("SELECT * FROM axiom.evidence_objects WHERE id = %s", (evidence_id,)).fetchone()
    if ev is None:
        return
    add("evidence_object", ev["id"], ref_digest=ev["observed_digest"], classification=ev["classification"],
        collected_at=ev["verified_at"], freshness="not_applicable", available=ev["status"] == "verified",
        attributes={"status": ev["status"], "media_type": ev["media_type"], "size": ev["observed_size"],
                    "original_filename": ev["original_filename"], "why_included": why})


def _occurrence_contradictions(occ, statuses, out):
    """Present in one run and absent/fixed in another is recorded, with which came last; never resolved here."""
    present = [s for s in statuses if s[1] == "present"]
    gone = [s for s in statuses if s[1] in ("absent_in_complete_scan", "fixed_by_source")]
    if present and gone:
        last = max(statuses, key=lambda s: s[0])
        out.append({"kind": "presence_disagreement", "occurrence_id": str(occ["id"]),
                    "vulnerability_ref": occ["vulnerability_ref"],
                    "latest_status": last[1], "description":
                    "observed present in at least one run and absent or fixed in another"})


def _attach_member_keys(contradictions, gaps, members, key_of):
    by_occ = {}
    for m in members:
        if m["kind"] == "occurrence_observation":
            by_occ.setdefault(m["attributes"]["occurrence_id"], []).append(m["member_key"])
    for item in contradictions + gaps:
        keys = []
        if "occurrence_id" in item:
            keys += [key_of.get(("occurrence", item["occurrence_id"]))] + by_occ.get(item["occurrence_id"], [])
        for oid in item.get("occurrence_ids", []):
            keys.append(key_of.get(("occurrence", oid)))
        if "asset_id" in item:
            keys.append(key_of.get(("asset", item["asset_id"])))
            keys += [m["member_key"] for m in members if m["kind"] == "business_context"
                     and m["attributes"]["asset_id"] == item["asset_id"]]
        if "evidence_id" in item:
            keys.append(key_of.get(("evidence_object", item["evidence_id"])))
        item["member_keys"] = sorted({k for k in keys if k})


# ------------------------------------------------------------------------------------------------- reading
def present_member(member: dict, authz: Authorizer, scope_id: UUID) -> dict:
    """A member as a given requester may see it: content (source text) needs evidence.read:<classification>;
    digests, sizes and filenames need evidence.read:<classification> or evidence.metadata:<classification>."""
    out = {k: member[k] for k in ("member_key", "kind", "ref_id", "classification", "collected_at", "freshness",
                                  "available")}
    attrs = dict(member["attributes"])
    cls = member["classification"]
    if cls:
        can_read = authz.has(EVIDENCE_READ[cls], scope_id)
        can_meta = can_read or authz.has(EVIDENCE_META[cls], scope_id)
        if not can_read and "source_text" in attrs:
            attrs["source_text"] = None
            out["content_withheld"] = f"requester lacks {EVIDENCE_READ[cls]}"
        if not can_meta:
            for f in ("original_filename", "size", "media_type"):
                attrs.pop(f, None)
            out["metadata_withheld"] = f"requester lacks {EVIDENCE_META[cls]}"
            out["ref_digest"] = None
        else:
            out["ref_digest"] = member["ref_digest"]
    else:
        out["ref_digest"] = member["ref_digest"]
    out["attributes"] = attrs
    return out


def withhold_for_route(pm: dict, route_max: str) -> bool:
    """Strip content **and** metadata of a presented member whose classification exceeds a model route's limit."""
    cls = pm.get("classification")
    if not cls or CLASS_RANK[cls] <= CLASS_RANK[route_max]:
        return False
    attrs = pm["attributes"]
    if "source_text" in attrs:
        attrs["source_text"] = None
    for f in ("original_filename", "size", "media_type", "raw_locator", "normalised"):
        attrs.pop(f, None)
    pm["ref_digest"] = None
    pm["content_withheld"] = f"{cls} content and metadata may not be sent to this model route"
    return True


def get_snapshot(conn, authz: Authorizer, snapshot_id: UUID) -> dict:
    snap = conn.execute("SELECT * FROM axiom.evidence_snapshots WHERE id = %s", (snapshot_id,)).fetchone()
    if snap is None or not authz.has("case.read", snap["scope_id"]):
        raise NotFound("snapshot not found", code="snapshot_not_found")
    members = conn.execute("SELECT * FROM axiom.evidence_snapshot_members WHERE snapshot_id = %s ORDER BY member_key",
                           (snapshot_id,)).fetchall()
    return {**snap, "members": [present_member(m, authz, snap["scope_id"]) for m in members]}


def verify_snapshot(conn, snapshot_id: UUID) -> bool:
    """Recompute the digest from stored rows (tamper check)."""
    conn.execute("SET LOCAL TimeZone = 'UTC'")
    snap = conn.execute("SELECT * FROM axiom.evidence_snapshots WHERE id = %s", (snapshot_id,)).fetchone()
    members = conn.execute("SELECT * FROM axiom.evidence_snapshot_members WHERE snapshot_id = %s ORDER BY member_key",
                           (snapshot_id,)).fetchall()
    body = {"case_id": str(snap["case_id"]), "as_of": _iso(snap["as_of"]),
            "freshness_policy_version_id": snap["freshness_policy_version_id"],
            "members": [{"member_key": m["member_key"], "kind": m["kind"], "ref_id": str(m["ref_id"]),
                         "ref_digest": m["ref_digest"], "classification": m["classification"],
                         "collected_at": _iso(m["collected_at"]), "freshness": m["freshness"],
                         "available": m["available"], "attributes": m["attributes"]} for m in members],
            "contradictions": snap["contradictions"], "gaps": snap["gaps"]}
    return hashlib.sha256(canonical(body)).hexdigest() == snap["digest"]
