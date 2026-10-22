"""Constrained, read-only investigation tools (INVS-02, A05; ADR 0012).

Rules enforced here, independent of what a model or source text asks for:

* Only tools in this registry exist, and a run may call only the tools granted when it was created. Grants are
  frozen on the run; nothing read during the run can add tools or change grants, permissions or policies.
* Arguments are typed (pydantic, unknown fields refused). Snapshot tools take **member keys** of the run's own
  snapshot, never record IDs, paths or URLs, so a tool cannot reach records outside the snapshot, scope or tenant.
* Network tools have a fixed, registered destination (scheme, host and path template). Model-generated or imported
  URLs are never fetched: the only network argument is an identifier checked against a strict pattern, and the
  destination must also be enabled for the installation (``AXIOM_TOOL_DESTINATIONS``) and granted on the run.
* Output is bounded in bytes; evidence content needs the requester's current classification permission and must not
  exceed the route's data classification; every content read is audited.
* Every call (refused ones included) is a recorded step with a request digest.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .. import audit
from ..domains.evidence.objectstore import TenantObjectStore
from .snapshots import CLASS_RANK, EVIDENCE_READ, present_member, withhold_for_route


class ToolRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MemberArgs(Args):
    member_key: str = Field(pattern=r"^M[0-9]{3,5}$")


class ExcerptArgs(Args):
    member_key: str = Field(pattern=r"^M[0-9]{3,5}$")
    offset: int = Field(default=0, ge=0, le=50_000_000)
    length: int = Field(default=2048, ge=1, le=4096)


class AdvisoryArgs(Args):
    # OSV identifiers such as CVE-2023-1234, GHSA-xxxx-xxxx-xxxx, DSA-1234-1, DEBIAN-CVE-...; no URLs or paths
    vulnerability_ref: str = Field(pattern=r"^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._-]{1,48}$")


@dataclass
class ToolContext:
    conn: object
    ctx: object
    authz: object
    run: dict
    snapshot: dict
    store: object | None
    route_max_classification: str
    http_transport: httpx.BaseTransport | None
    enabled_destinations: frozenset[str]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args: type[Args]
    destination: str            # "platform:<what>" or a registered https origin
    max_output_bytes: int
    handler: Callable[[ToolContext, Args], dict]
    description: str


def _member(tc: ToolContext, key: str) -> dict:
    m = tc.conn.execute("SELECT * FROM axiom.evidence_snapshot_members WHERE snapshot_id = %s AND member_key = %s",
                        (tc.snapshot["id"], key)).fetchone()
    if m is None:
        raise ToolRefused("unknown_member", f"{key} is not a member of this run's snapshot")
    return m


def _snapshot_member(tc: ToolContext, a: MemberArgs) -> dict:
    m = _member(tc, a.member_key)
    out = present_member(m, tc.authz, tc.snapshot["scope_id"])
    withhold_for_route(out, tc.route_max_classification)
    return out


def _evidence_excerpt(tc: ToolContext, a: ExcerptArgs) -> dict:
    m = _member(tc, a.member_key)
    if m["kind"] == "evidence_object":
        evidence_id = m["ref_id"]
    elif m["kind"] == "observation":
        evidence_id = m["attributes"]["raw_evidence_id"]
    else:
        raise ToolRefused("not_evidence", f"{a.member_key} is a {m['kind']}, not evidence")
    ev = tc.conn.execute("SELECT * FROM axiom.evidence_objects WHERE id = %s", (evidence_id,)).fetchone()
    if ev is None or ev["status"] != "verified":
        raise ToolRefused("evidence_unavailable", "evidence is not verified")
    if CLASS_RANK[ev["classification"]] > CLASS_RANK[tc.route_max_classification]:
        raise ToolRefused("classification_exceeds_route",
                          f"{ev['classification']} evidence may not be sent to this model route")
    # the requester's authority, re-checked at the time of the read
    if not tc.authz.has(EVIDENCE_READ[ev["classification"]], ev["scope_id"], principal_id=tc.run["requested_by"]):
        raise ToolRefused("requester_lacks_permission", f"requester lacks {EVIDENCE_READ[ev['classification']]}")
    data = b"".join(TenantObjectStore(tc.store, tc.ctx.tenant_id).get(ev["object_key"]))
    if hashlib.sha256(data).hexdigest() != ev["observed_digest"]:
        raise ToolRefused("evidence_integrity", "stored evidence does not match its verified digest")
    chunk = data[a.offset:a.offset + a.length]
    audit.record(tc.conn, tc.ctx, action="evidence.read", resource_type="evidence", resource_id=ev["id"],
                 detail={"purpose": "investigation", "run_id": str(tc.run["id"]), "offset": a.offset,
                         "bytes": len(chunk), "on_behalf_of": str(tc.run["requested_by"])})
    return {"member_key": a.member_key, "offset": a.offset, "bytes": len(chunk), "total_size": len(data),
            "text": chunk.decode("utf-8", errors="replace")}


def _asset_history(tc: ToolContext, a: MemberArgs) -> dict:
    m = _member(tc, a.member_key)
    if m["kind"] != "asset":
        raise ToolRefused("not_asset", f"{a.member_key} is a {m['kind']}, not an asset")
    rows = tc.conn.execute(
        """SELECT deployment_digest, version_label, observed_at FROM axiom.asset_versions
            WHERE asset_id = %s AND created_at <= %s ORDER BY observed_at DESC LIMIT 50""",
        (m["ref_id"], tc.snapshot["as_of"])).fetchall()
    return {"member_key": a.member_key, "versions": [{**r, "observed_at": r["observed_at"].isoformat()} for r in rows],
            "note": "versions recorded up to the snapshot time"}


OSV = "https://api.osv.dev"


def _advisory_lookup(tc: ToolContext, a: AdvisoryArgs) -> dict:
    if OSV not in tc.enabled_destinations:
        raise ToolRefused("destination_not_enabled", f"{OSV} is not an enabled destination for this installation")
    url = f"{OSV}/v1/vulns/{a.vulnerability_ref}"           # fixed template; identifier already pattern-checked
    try:
        with httpx.Client(transport=tc.http_transport, timeout=10, follow_redirects=False) as c:
            r = c.get(url, headers={"accept": "application/json"})
    except httpx.HTTPError as exc:
        raise ToolRefused("destination_unavailable", f"advisory source unreachable: {type(exc).__name__}") from exc
    if r.status_code == 404:
        return {"vulnerability_ref": a.vulnerability_ref, "found": False}
    if r.status_code != 200:
        raise ToolRefused("destination_error", f"advisory source returned {r.status_code}")
    try:
        d = r.json()
    except ValueError as exc:
        raise ToolRefused("destination_error", "advisory response is not JSON") from exc
    # documented fields only (OSV GET /v1/vulns/{id}); reference URLs are returned as text and never fetched
    return {"vulnerability_ref": a.vulnerability_ref, "found": True, "source": "OSV (external, untrusted)",
            "id": d.get("id"), "summary": (d.get("summary") or "")[:500], "details": (d.get("details") or "")[:2000],
            "modified": d.get("modified"), "published": d.get("published"),
            "affected_packages": sorted({(x.get("package") or {}).get("name", "") for x in d.get("affected", [])
                                         if isinstance(x, dict)} - {""})[:20],
            "reference_urls_not_fetched": [ref.get("url") for ref in d.get("references", [])
                                           if isinstance(ref, dict)][:10]}


REGISTRY: dict[str, ToolSpec] = {t.name: t for t in (
    ToolSpec("snapshot_member", MemberArgs, "platform:snapshot", 16_384, _snapshot_member,
             "Full frozen attributes of one snapshot member (source text only where readable)."),
    ToolSpec("evidence_excerpt", ExcerptArgs, "platform:evidence", 8_192, _evidence_excerpt,
             "Bytes of a verified evidence object behind a snapshot member (at most 4096 per call)."),
    ToolSpec("asset_history", MemberArgs, "platform:assets", 8_192, _asset_history,
             "Deployment versions recorded for a snapshot asset up to the snapshot time."),
    ToolSpec("advisory_lookup", AdvisoryArgs, OSV, 8_192, _advisory_lookup,
             "Public OSV advisory by identifier (external; disabled unless enabled and granted)."),
)}
DEFAULT_GRANTS = ("snapshot_member", "evidence_excerpt", "asset_history")


def run_tool(tc: ToolContext, name: str, arguments: dict) -> tuple[str, dict]:
    """Return (status, result). Status is 'completed' or 'refused'; refusals carry a code and are not errors."""
    spec = REGISTRY.get(name)
    if spec is None:
        return "refused", {"code": "unknown_tool", "message": f"no tool named {name!r}"}
    if name not in {g["tool"] for g in tc.run["tool_grants"]}:
        return "refused", {"code": "not_granted", "message": f"{name} is not granted to this run"}
    try:
        args = spec.args.model_validate(arguments if isinstance(arguments, dict) else {})
    except ValidationError as exc:
        return "refused", {"code": "invalid_arguments", "message": "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}" for e in exc.errors()[:5])}
    try:
        result = spec.handler(tc, args)
    except ToolRefused as exc:
        return "refused", {"code": exc.code, "message": str(exc)}
    body = json.dumps(result, default=str)
    if len(body.encode()) > spec.max_output_bytes:
        result = {"truncated": True, "max_output_bytes": spec.max_output_bytes,
                  "partial": body.encode()[:spec.max_output_bytes].decode("utf-8", errors="ignore")}
    return "completed", result


def validate_grants(requested: list[str], enabled_destinations: frozenset[str]) -> list[dict]:
    grants = []
    for name in requested:
        spec = REGISTRY.get(name)
        if spec is None:
            raise ValueError(f"unknown tool {name!r}")
        if not spec.destination.startswith("platform:") and spec.destination not in enabled_destinations:
            raise ValueError(f"{name} needs destination {spec.destination}, which is not enabled for this installation")
        grants.append({"tool": name, "destination": spec.destination, "max_output_bytes": spec.max_output_bytes})
    return grants

