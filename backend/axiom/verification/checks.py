"""Check-endpoint contract ``axiom-check/2``, the destination policy, and the explicit rules that turn a response into an outcome (ADR 0014).

The platform does not scan anything itself. A *check endpoint* (configured as a connection with adapter
``verification_check``) is asked whether the original condition of a case is still present on a named deployment.
Only a local fixture endpoint has been tested; no real scanner or check service has been integrated.

Request (POST ``{base_url}/v1/checks``, JSON)::

    {"schema": "axiom-check/2", "request_id": "<job id>", "nonce": "<random per attempt>",
     "asset": {"id": "...", "kind": "...", "name": "..."},
     "deployment_digest": "sha256:...",
     "criteria": [{"id": "original_condition", "kind": "finding_absent",
                   "conditions": [{"vulnerability_ref": "CVE-...", "component": "openssl@3.0.1"}]}]}

Response (200, JSON, at most 1 MiB)::

    {"schema": "axiom-check/2", "request_id": "<echoed>", "nonce": "<echoed>", "asset_id": "<echoed>",
     "observed_at": "<RFC 3339 time the target was examined>",
     "deployment_digest": "<digest the endpoint actually examined>", "coverage": "complete" | "partial",
     "results": [{"criterion": "original_condition", "result": "absent" | "present" | "error", "detail": "..."}]}

Rules (``assess``), applied in this order; the first that matches decides:

====  ==========================  ===============  ============================================================
 #    rule                        outcome          when
====  ==========================  ===============  ============================================================
 1    target_refused              inconclusive     HTTP status other than 200 (redirects are not followed)
 2    malformed_response          inconclusive     body too large, not JSON, wrong schema, bad fields
 2b   unbound_response            inconclusive     request id, nonce or asset id not echoed exactly
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

Destination policy (``DestinationPolicy``). The endpoint is whatever a connection with ``connection.configure``
authority names; analysts and imported data cannot change it. On top of that, the worker only calls origins listed in
``AXIOM_VERIFICATION_DESTINATIONS`` (none by default, so nothing is called until an operator allows it). The host is
resolved once per attempt and every address must be allowed: inside ``AXIOM_VERIFICATION_NETWORKS`` when that is
set, otherwise outside loopback, link-local (including cloud metadata), unspecified and multicast ranges. The
connection is made to the checked address, with TLS verified against the configured hostname, so a later DNS answer
cannot redirect it. A refused destination or an untrusted certificate parks the job for an operator; it says nothing
about the case. The bearer credential is sent only on that one request, and if a response echoes it, it is redacted
before the response is stored.

What a response establishes: that the configured, TLS-authenticated endpoint answered this request (nonce, request
and asset echoed) with these claims. The claims themselves (examined digest, observation time, results) are the
endpoint's assertions; nothing signs them, and the platform's own timestamps (sent, received) are not evidence of
when or whether the endpoint examined anything.

\\* The case service recomputes the recorded outcome (``model.verification_outcome``); a pass additionally needs the
response preserved as verified evidence. A claimed pass is only ever downgraded.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx

SCHEMA = "axiom-check/2"
MAX_RESPONSE_BYTES = 1 << 20
FUTURE_SKEW = timedelta(minutes=5)
DIGEST = re.compile(r"^[a-z0-9]+:[0-9a-f]{32,128}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
REDACTED = b"[redacted credential]"

# Refused unless AXIOM_VERIFICATION_NETWORKS explicitly allows them.
DEFAULT_BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128"))


class CheckUnavailable(Exception):
    """Transient: connection failure, timeout, HTTP 429 or 5xx. The message never contains credentials."""


class DestinationRefused(Exception):
    """The destination is not allowed by policy, or its certificate is not trusted. Not retried."""


@dataclass(frozen=True)
class Exchange:
    status: int
    body: bytes
    truncated: bool
    sent_at: datetime
    received_at: datetime
    connected_address: str | None = None
    redacted: bool = False


def origin(base_url: str) -> str:
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    return f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")


def _normal_origin(url: str) -> str:
    parts = urlsplit(url.strip())
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}:{port}"


@dataclass(frozen=True)
class DestinationPolicy:
    origins: frozenset[str] = frozenset()
    networks: tuple = ()

    @classmethod
    def from_settings(cls, destinations: str = "", networks: str = "") -> "DestinationPolicy":
        return cls(frozenset(_normal_origin(o) for o in destinations.split(",") if o.strip()),
                   tuple(ipaddress.ip_network(n.strip(), strict=False) for n in networks.split(",") if n.strip()))

    def check_origin(self, base_url: str) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or parts.username or parts.password:
            raise DestinationRefused("check endpoints must be plain https:// URLs without credentials")
        if _normal_origin(base_url) not in self.origins:
            raise DestinationRefused(f"{origin(base_url)} is not an allowed verification destination")

    def check_addresses(self, addresses: list[str]) -> None:
        if not addresses:
            raise DestinationRefused("the destination did not resolve to any address")
        for a in addresses:
            ip = ipaddress.ip_address(a)
            if self.networks:
                if not any(ip in n for n in self.networks):
                    raise DestinationRefused(f"resolved address {ip} is outside the allowed networks")
            elif any(ip in n for n in DEFAULT_BLOCKED):
                raise DestinationRefused(f"resolved address {ip} is in a range that is never contacted by default")


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise CheckUnavailable("check endpoint name did not resolve") from None
    return list(dict.fromkeys(i[4][0] for i in infos))


def _tls_failure(exc: BaseException) -> bool:
    while exc is not None:
        if isinstance(exc, ssl.SSLError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class CheckEndpointClient:
    """One POST per check to an allowed, pinned address. Redirects are not followed, the body is capped, and the
    credential goes only in the Authorization header of that request."""

    def __init__(self, base_url: str, token: Callable[[], str | None] | None = None, *, policy: DestinationPolicy,
                 resolver: Callable[[str, int], list[str]] = system_resolver, timeout: float = 15.0,
                 verify: bool | ssl.SSLContext = True, clock: Callable[[], datetime]):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.policy = policy
        self.resolver = resolver
        self.timeout = timeout
        self.verify = verify
        self.clock = clock

    def run(self, request: dict) -> Exchange:
        self.policy.check_origin(self.base_url)
        parts = urlsplit(self.base_url)
        host, port = parts.hostname, parts.port or 443
        addresses = self.resolver(host, port)
        self.policy.check_addresses(addresses)
        address = addresses[0]
        literal = f"[{address}]" if ":" in address else address
        url = f"https://{literal}:{port}{parts.path}/v1/checks"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "Host": host if port == 443 else f"{host}:{port}"}
        token = self._token() if self._token else None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        sent_at = self.clock()
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify, follow_redirects=False, trust_env=False) as c:
                with c.stream("POST", url, headers=headers, content=json.dumps(request).encode(),
                              extensions={"sni_hostname": host}) as r:
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
            if _tls_failure(exc):
                raise DestinationRefused("the check endpoint's TLS certificate was not trusted for its hostname") from None
            raise CheckUnavailable(f"check endpoint unreachable ({type(exc).__name__})") from None
        if status == 429 or status >= 500:
            raise CheckUnavailable(f"check endpoint returned HTTP {status}")
        data, redacted = bytes(body[:MAX_RESPONSE_BYTES]), False
        if token and token.encode() in data:
            data, redacted = data.replace(token.encode(), REDACTED), True
        return Exchange(status, data, truncated, sent_at, self.clock(), address, redacted)


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


def assess(exchange: Exchange, *, request_id: str, nonce: str, asset_id: str, criteria: list[str],
           target_digest: str | None, change_reported_at: datetime, max_age: timedelta) -> Assessment:
    if exchange.status != 200:
        return inconclusive("target_refused", f"check endpoint answered HTTP {exchange.status}")
    if exchange.truncated:
        return inconclusive("malformed_response", "response larger than the 1 MiB limit")
    try:
        doc = json.loads(exchange.body)
    except (ValueError, UnicodeDecodeError):
        return inconclusive("malformed_response", "response is not JSON")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA \
            or not isinstance(doc.get("results"), list) or doc.get("coverage") not in ("complete", "partial"):
        return inconclusive("malformed_response", f"response does not follow {SCHEMA}")
    if doc.get("request_id") != request_id or doc.get("nonce") != nonce or doc.get("asset_id") != asset_id:
        return inconclusive("unbound_response", "response does not echo this request's id, nonce and asset")
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
