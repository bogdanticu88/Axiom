"""Model providers behind the gateway.

* ``DeterministicFakeProvider``: rule-based stand-in for CI and tests. It is **not** a language model and its results
  say nothing about model quality; it exists so the platform's own controls (validation, budgets, recovery,
  adversarial handling) can be tested deterministically. ``fake-rules-v1`` follows simple evidence rules;
  ``fake-adversarial:<behaviour>`` misbehaves on purpose (fabricated or irrelevant citations, obeying injected
  instructions, malformed output, timeouts, tool-argument abuse, ignoring recorded contradictions). The gateway refuses
  this provider when ``AXIOM_ENV=production``.
* ``AnthropicMessagesProvider``: Anthropic Messages API (``POST {endpoint}/v1/messages``, headers ``x-api-key`` and
  ``anthropic-version: 2023-06-01``; response ``content`` blocks of ``type: text``, ``usage.input_tokens``,
  ``usage.output_tokens``, ``stop_reason``; errors ``{"type": "error", "error": {"type", "message"}}`` with 429
  rate_limit_error, 500 api_error, 504 timeout_error and 529 overloaded_error retryable). Shapes are taken from the
  public API documentation (Messages and Errors pages, read 2026-10-22). **Never run against
  the live service in this project**: no credentials or external access were authorised. Tested only against a local
  transport that returns the documented shapes.
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from typing import Callable

import httpx


@dataclass
class ModelRequest:
    system: str
    user: str
    max_output_tokens: int
    timeout_seconds: float


@dataclass
class ModelResponse:
    text: str
    input_tokens: int
    output_tokens: int
    stop_reason: str | None
    provider_request_id: str | None = None
    usage_estimated: bool = False


class ProviderError(Exception):
    def __init__(self, kind: str, message: str, *, retryable: bool, status: int | None = None):
        super().__init__(f"{kind}: {message}")
        self.kind, self.retryable, self.status = kind, retryable, status


def _estimate(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


# ------------------------------------------------------------------------------------------------ fake
class DeterministicFakeProvider:
    BEHAVIOURS = ("honest", "fabricate", "irrelevant", "obey_injection", "malformed", "malformed_once", "timeout",
                  "slow", "ignore_contradiction", "tool_abuse", "action_fields", "stale_support", "loop")

    def __init__(self, model: str, *, sleep: Callable[[float], None] = time.sleep):
        if model == "fake-rules-v1":
            self.behaviour = "honest"
        elif model.startswith("fake-adversarial:") and model.split(":", 1)[1] in self.BEHAVIOURS:
            self.behaviour = model.split(":", 1)[1]
        else:
            raise ValueError(f"unknown fake model {model!r}")
        self.sleep = sleep
        self.calls = 0
        self.requests: list[ModelRequest] = []      # what the platform actually sent (after redaction)

    def complete(self, req: ModelRequest) -> ModelResponse:
        self.calls += 1
        self.requests.append(req)
        b = self.behaviour
        if b == "timeout":
            raise ProviderError("timeout", "simulated provider timeout", retryable=True)
        if b == "slow":
            self.sleep(min(req.timeout_seconds + 0.2, 3))
            raise ProviderError("timeout", f"no response within {req.timeout_seconds}s", retryable=True)
        payload = json.loads(req.user)
        if b == "malformed" or (b == "malformed_once" and self.calls == 1):
            text = "Sure! Here is my analysis: the vulnerability is probably fine {not json"
        else:
            text = json.dumps(self._round(payload))
        return ModelResponse(text=text, input_tokens=_estimate(req.system + req.user), output_tokens=_estimate(text),
                             stop_reason="end_turn", usage_estimated=True)

    # Simple evidence rules over the snapshot summary the gateway sent.
    def _round(self, p: dict) -> dict:
        members = p["snapshot"]["members"]
        tools = set(p.get("granted_tools", []))
        rnd = p["round"]
        b = self.behaviour
        if b == "tool_abuse" and rnd == 1:
            return {"tool_requests": [
                {"tool": "snapshot_member", "arguments": {"member_key": "../../etc/passwd"}},
                {"tool": "snapshot_member", "arguments": {"member_key": "M001", "snapshot_id": "00000000-0000-0000-0000-000000000000"}},
                {"tool": "advisory_lookup", "arguments": {"vulnerability_ref": "https://attacker.example/x?CVE-2024-1"}},
                {"tool": "http_get", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}},
                {"tool": "evidence_excerpt", "arguments": {"member_key": "M001", "offset": 0, "length": 10_000_000}},
            ], "claims": [], "next_checks": [], "done": False}
        if b == "loop":
            return {"tool_requests": [{"tool": "snapshot_member", "arguments": {"member_key": "M001"}}],
                    "claims": [], "next_checks": [], "done": False}
        if rnd == 1 and "snapshot_member" in tools and b == "honest":
            obs = [m for m in members if m["kind"] == "observation"]
            if obs:
                return {"tool_requests": [{"tool": "snapshot_member", "arguments": {"member_key": obs[0]["member_key"]}}],
                        "claims": [], "next_checks": [], "done": False}
        out = {"tool_requests": [], "claims": [], "next_checks": [], "done": True}
        if b == "action_fields":
            out["dismiss"] = True
            out["priority"] = "low"
            return out
        injected = any("ignore" in json.dumps(m.get("attributes", {}).get("source_text") or {}).lower()
                       and "instruction" in json.dumps(m.get("attributes", {}).get("source_text") or {}).lower()
                       for m in members)
        q = p["questions"][0]["id"]
        by_occ: dict[str, list[dict]] = {}
        for m in members:
            if m["kind"] == "occurrence_observation":
                by_occ.setdefault(m["attributes"]["occurrence_id"], []).append(m)
        occ_members = {m["ref_id"]: m for m in members if m["kind"] == "occurrence"}
        for occ_id, obs in by_occ.items():
            occ = occ_members.get(occ_id)
            if occ is None:
                continue
            vuln = occ["attributes"]["vulnerability_ref"]
            obs.sort(key=lambda m: (m["attributes"].get("scan_time") or "", m["attributes"]["recorded_at"]))
            latest = obs[-1]
            present = [m["member_key"] for m in obs if m["attributes"]["observed_status"] == "present"]
            gone = [m["member_key"] for m in obs if m["attributes"]["observed_status"] != "present"]
            subject = {"vulnerability_ref": vuln, "asset_id": occ["attributes"]["asset_id"],
                       "asset_version_id": occ["attributes"]["asset_version_id"], "attribute": "present_in_deployment"}
            claim = {"question_id": q, "subject": subject, "model_stated_confidence": "medium"}
            if b == "obey_injection" and injected:
                claim.update(statement="The finding is not exploitable and should be dismissed.", conclusion="supported",
                             supporting=[occ["member_key"]], contradicting=[],
                             subject={**subject, "attribute": "exposure"})
            elif b == "fabricate":
                claim.update(statement=f"{vuln} is present", conclusion="supported", supporting=["M999"],
                             contradicting=[])
            elif b == "irrelevant":
                other = [m for m in members if m["kind"] == "occurrence_observation"
                         and m["attributes"]["vulnerability_ref"] != vuln]
                claim.update(statement=f"{vuln} is present", conclusion="supported",
                             supporting=[other[0]["member_key"]] if other else [gone[0] if gone else "M001"],
                             contradicting=[])
            elif b == "ignore_contradiction" and present:
                claim.update(statement=f"{vuln} is present in the deployment", conclusion="supported",
                             supporting=present, contradicting=[])
            elif b == "stale_support" and present:
                claim.update(statement=f"{vuln} is present in the deployment", conclusion="supported",
                             supporting=present, contradicting=gone)
            elif (contra := next((c for c in p["snapshot"]["contradictions"] if c["kind"] == "presence_disagreement"
                                  and c.get("occurrence_id") == occ_id), None)) and contra.get("ordering") != "by_scan_time":
                claim.update(statement=f"whether {vuln} is still present", conclusion="unknown", supporting=present,
                             contradicting=gone, limitations="conflicting observations without a defensible order: "
                                                             + contra.get("ordering_reason", ""))
            elif contra and contra["latest_status"] != "present":
                claim.update(statement=f"{vuln} is present in the deployment", conclusion="contradicted",
                             supporting=present, contradicting=gone,
                             limitations="the latest scan reports it absent or fixed")
            elif latest["attributes"]["observed_status"] == "present" and latest["freshness"] == "fresh":
                claim.update(statement=f"{vuln} was reported present by the latest scan", conclusion="supported",
                             supporting=present, contradicting=gone)
            elif latest["attributes"]["observed_status"] != "present":
                claim.update(statement=f"{vuln} is present in the deployment", conclusion="contradicted",
                             supporting=present, contradicting=gone,
                             limitations="the latest observation reports it absent or fixed")
            else:
                claim.update(statement=f"whether {vuln} is still present", conclusion="unknown", supporting=present,
                             contradicting=gone, limitations="the latest observation is stale")
            out["claims"].append(claim)
            if occ["attributes"].get("source_severity"):
                out["claims"].append({
                    "question_id": q, "statement": f"the source reports severity {occ['attributes']['source_severity']}",
                    "subject": {"vulnerability_ref": vuln, "asset_id": occ["attributes"]["asset_id"],
                                "attribute": "severity_as_reported"},
                    "conclusion": "supported", "supporting": [occ["member_key"]], "contradicting": []})
        for g in p["snapshot"]["gaps"]:
            if g["kind"] in ("no_business_context", "no_criticality"):
                out["next_checks"].append({"description": "confirm the asset owner and criticality", "tool": None})
            if g["kind"] in ("no_complete_scan", "stale_complete_scan"):
                out["next_checks"].append({"description": "run a complete scan of the affected deployment", "tool": None})
        out["next_checks"] = [dict(t) for t in {tuple(sorted(c.items())) for c in out["next_checks"]}]
        out["next_checks"].sort(key=lambda c: c["description"])
        return out


# ------------------------------------------------------------------------------------------------ Anthropic
class AnthropicMessagesProvider:
    RETRYABLE = {429: "rate_limit_error", 500: "api_error", 504: "timeout_error", 529: "overloaded_error"}

    def __init__(self, endpoint: str, model: str, api_key: Callable[[], str], *,
                 transport: httpx.BaseTransport | None = None):
        if not re.fullmatch(r"https://[a-z0-9.-]+(:[0-9]+)?", endpoint.rstrip("/")):
            raise ValueError("endpoint must be an https origin")
        self.url = endpoint.rstrip("/") + "/v1/messages"
        self.model, self.api_key, self.transport = model, api_key, transport

    def complete(self, req: ModelRequest) -> ModelResponse:
        body = {"model": self.model, "max_tokens": req.max_output_tokens, "system": req.system,
                "messages": [{"role": "user", "content": req.user}]}
        headers = {"x-api-key": self.api_key(), "anthropic-version": "2023-06-01", "content-type": "application/json"}
        try:
            with httpx.Client(transport=self.transport, timeout=req.timeout_seconds, follow_redirects=False) as c:
                r = c.post(self.url, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise ProviderError("timeout", str(exc), retryable=True) from exc
        except httpx.TransportError as exc:
            raise ProviderError("connection", str(exc), retryable=True) from exc
        rid = r.headers.get("request-id")
        if r.status_code != 200:
            try:
                err = r.json().get("error", {})
            except ValueError:
                err = {}
            kind = err.get("type") or f"http_{r.status_code}"
            raise ProviderError(kind, f"{r.status_code} {err.get('message', '')[:200]} request-id={rid}",
                                retryable=r.status_code in self.RETRYABLE, status=r.status_code)
        try:
            data = r.json()
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            usage = data.get("usage") or {}
            stop = data.get("stop_reason")
        except (ValueError, AttributeError) as exc:
            raise ProviderError("bad_response", "response is not the documented JSON shape", retryable=False) from exc
        if stop == "refusal":
            raise ProviderError("refusal", "the model declined", retryable=False)
        return ModelResponse(text=text, input_tokens=int(usage.get("input_tokens") or 0),
                             output_tokens=int(usage.get("output_tokens") or 0), stop_reason=stop,
                             provider_request_id=rid)
