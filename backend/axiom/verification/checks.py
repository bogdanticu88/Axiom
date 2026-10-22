"""Check-endpoint contract ``axiom-check/1`` and the explicit rules that turn a response into an outcome (ADR 0014).

The platform does not scan anything itself. A *check endpoint* (configured as a connection with adapter
``verification_check``) is asked whether the original condition of a case is still present on a named deployment.
Only a local fixture endpoint has been tested; no real scanner or check service has been integrated.

Request (POST ``{base_url}/v1/checks``, JSON)::

    {"schema": "axiom-check/1", "request_id": "<job id>", "asset": {"id": "...", "kind": "...", "name": "..."},
     "deployment_digest": "sha256:...",
     "criteria": [{"id": "original_condition", "kind": "finding_absent",
                   "conditions": [{"vulnerability_ref": "CVE-...", "component": "openssl@3.0.1"}]}]}

Response (200, JSON, at most 1 MiB)::

    {"schema": "axiom-check/1", "request_id": "<echoed>", "observed_at": "<RFC 3339 time the target was examined>",
     "deployment_digest": "<digest the endpoint actually examined>", "coverage": "complete" | "partial",
     "results": [{"criterion": "original_condition", "result": "absent" | "present" | "error", "detail": "..."}]}

Rules (``assess``), applied in this order; the first that matches decides:

====  ==========================  ===============  ============================================================
 #    rule                        outcome          when
====  ==========================  ===============  ============================================================
 1    target_refused              inconclusive     HTTP status other than 200 (redirects are not followed)
 2    malformed_response          inconclusive     body too large, not JSON, wrong schema or request id, bad fields
 3    deployment_unknown          inconclusive     no valid deployment digest in the response
 4    observation_time_unknown    inconclusive     observed_at missing or not an RFC 3339 time with offset
 5    observation_time_in_future  inconclusive     observed_at more than 5 minutes after the response arrived
 6    observation_stale           inconclusive     observed_at older than the connection's maximum age
 7    observation_predates_change inconclusive     observed_at before the change was reported
 8    different_deployment        inconclusive     the examined deployment is not the reported one
 9    contradictory_results       inconclusive     one criterion reported with different results
 10   condition_present           failed           any requested criterion reported ``present``
 11   incomplete_coverage         inconclusive     coverage partial, or a criterion missing or ``error``
 12   condition_absent            passed*          every criterion ``absent`` and coverage complete
====  ==========================  ===============  ============================================================

``unavailable`` (connection error, timeout, HTTP 429 or 5xx) is retried by the job; when the job's last attempt is
also unavailable the outcome is inconclusive with rule ``target_unavailable``. A case with no vulnerability reference
on the reported asset is not sent to the endpoint: inconclusive, rule ``no_checkable_condition``.

\\* The case service recomputes the recorded outcome (``model.verification_outcome``); a pass additionally needs the
response preserved as verified evidence. A claimed pass is only ever downgraded.
"""
from __future__ import annotations

import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx

SCHEMA = "axiom-check/1"
MAX_RESPONSE_BYTES = 1 << 20
FUTURE_SKEW = timedelta(minutes=5)
DIGEST = re.compile(r"^[a-z0-9]+:[0-9a-f]{32,128}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


class CheckUnavailable(Exception):
    """Transient: connection failure, timeout, HTTP 429 or 5xx. The message never contains credentials."""


@dataclass(frozen=True)
class Exchange:
    status: int
    body: bytes
    truncated: bool
    sent_at: datetime
    received_at: datetime


def origin(base_url: str) -> str:
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    return f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")


class CheckEndpointClient:
    """One POST per check. Redirects are not followed, the body is capped, credentials go only in the header."""

    def __init__(self, base_url: str, token: Callable[[], str | None] | None = None, *, timeout: float = 15.0,
                 verify: bool | ssl.SSLContext = True, clock: Callable[[], datetime]):
        self.url = base_url.rstrip("/") + "/v1/checks"
        self._token = token
        self.timeout = timeout
        self.verify = verify
        self.clock = clock

    def run(self, request: dict) -> Exchange:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = self._token() if self._token else None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        sent_at = self.clock()
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify, follow_redirects=False, trust_env=False) as c:
                with c.stream("POST", self.url, headers=headers, content=json.dumps(request).encode()) as r:
                    body, truncated = bytearray(), False
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > MAX_RESPONSE_BYTES:
                            truncated = True
                            break
                    status = r.status_code
        except httpx.TimeoutException:
            raise CheckUnavailable("check endpoint timed out") from None
        except httpx.HTTPError as exc:
            raise CheckUnavailable(f"check endpoint unreachable ({type(exc).__name__})") from None
        if status == 429 or status >= 500:
            raise CheckUnavailable(f"check endpoint returned HTTP {status}")
        return Exchange(status, bytes(body[:MAX_RESPONSE_BYTES]), truncated, sent_at, self.clock())


@dataclass(frozen=True)
class Assessment:
    claimed: str                     # passed | failed | inconclusive (the service may only downgrade it)
    coverage: str                    # complete | partial | none
    rule: str
    explanation: str
    observed_digest: str | None = None
    observed_at: datetime | None = None


def _time(value) -> datetime | None:
    if not isinstance(value, str) or not _RFC3339.match(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def inconclusive(rule: str, explanation: str, **kw) -> Assessment:
    return Assessment("inconclusive", "none", rule, explanation, **kw)


def assess(exchange: Exchange, *, request_id: str, criteria: list[str], target_digest: str | None,
           change_reported_at: datetime, max_age: timedelta) -> Assessment:
    if exchange.status != 200:
        return inconclusive("target_refused", f"check endpoint answered HTTP {exchange.status}")
    if exchange.truncated:
        return inconclusive("malformed_response", "response larger than the 1 MiB limit")
    try:
        doc = json.loads(exchange.body)
    except (ValueError, UnicodeDecodeError):
        return inconclusive("malformed_response", "response is not JSON")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or doc.get("request_id") != request_id \
            or not isinstance(doc.get("results"), list) or doc.get("coverage") not in ("complete", "partial"):
        return inconclusive("malformed_response", f"response does not follow {SCHEMA} for this request")
    digest = doc.get("deployment_digest")
    if not isinstance(digest, str) or not DIGEST.match(digest):
        return inconclusive("deployment_unknown", "response does not name the examined deployment")
    observed_at = _time(doc.get("observed_at"))
    if observed_at is None:
        return inconclusive("observation_time_unknown", "response has no valid observation time", observed_digest=digest)
    seen = {"observed_digest": digest, "observed_at": observed_at}
    if observed_at > exchange.received_at + FUTURE_SKEW:
        return inconclusive("observation_time_in_future", "observation time is in the future", **seen)
    if exchange.received_at - observed_at > max_age:
        return inconclusive("observation_stale", f"observation older than {int(max_age.total_seconds())} s", **seen)
    if observed_at < change_reported_at:
        return inconclusive("observation_predates_change", "observation was made before the change was reported", **seen)
    if digest != target_digest:
        return inconclusive("different_deployment", "endpoint examined a different deployment than the one reported",
                            **seen)
    results: dict[str, set[str]] = {}
    for item in doc["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("criterion"), str) \
                or item.get("result") not in ("absent", "present", "error"):
            return inconclusive("malformed_response", "a result entry is malformed", **seen)
        results.setdefault(item["criterion"], set()).add(item["result"])
    requested = {c: results.get(c, set()) for c in criteria}
    if any(len(v) > 1 for v in requested.values()):
        return inconclusive("contradictory_results", "a criterion was reported with different results", **seen)
    if any(v == {"present"} for v in requested.values()):
        covered = "complete" if doc["coverage"] == "complete" and all(v for v in requested.values()) else "partial"
        return Assessment("failed", covered, "condition_present",
                          "the original condition is still present on the reported deployment", **seen)
    if doc["coverage"] != "complete" or any(v != {"absent"} for v in requested.values()):
        return Assessment("inconclusive", "partial", "incomplete_coverage",
                          "not every criterion was checked completely", **seen)
    return Assessment("passed", "complete", "condition_absent",
                      "every criterion reported absent on the reported deployment", **seen)
