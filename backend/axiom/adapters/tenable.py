"""Tenable Vulnerability Management: vulnerability export chunk parser and export API client.

References checked 2026-10-22 (developer.tenable.com): POST /vulns/export (body: num_assets 50..5000,
filters incl. state OPEN|REOPENED|FIXED, since/first_found/last_found/last_fixed as Unix seconds; response
export_uuid; 409 for a duplicate active export with active_job_id), GET /vulns/export/{uuid}/status
(status QUEUED|PROCESSING|FINISHED|CANCELLED|ERROR, chunks_available, chunks_failed, chunks_cancelled,
total_chunks), GET /vulns/export/{uuid}/chunks/{chunk_id} (chunks expire after 24 hours; empty attributes
omitted), 429 with a `retry-after` header in seconds. Without time filters an export covers only the last
30 days, so an export is never treated as a complete inventory.

Support level: fixture-tested against SYNTHETIC chunks and a local fake API. Not validated against a live
Tenable instance (no licensed account available).
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import httpx

from .base import (AdapterInfo, FindingRecord, Identifier, ParseError, ParseEvent, Quarantine, ScanSummary,
                   SubjectHints, SupportLevel, load_json, parse_time, pointer, stable_digest)

INFO = AdapterInfo(
    name="tenable_vm", version="1.0.0", adapter_kind="scanner", formats=("tenable-vulns-export-chunk",),
    operations=("file_import", "api_sync"), support_level=SupportLevel.FIXTURE_TESTED,
    validation_notes="Synthetic fixtures shaped from public API documentation and a local fake server only. "
                     "Requires a licensed Tenable Vulnerability Management account for sandbox validation.")

_STATES = {"OPEN": "open", "REOPENED": "open", "FIXED": "fixed"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class TenableChunkParser:
    info = INFO

    def parse(self, data: bytes, *, declared_subject: SubjectHints | None = None) -> Iterator[ParseEvent]:
        records = load_json(data)
        if not isinstance(records, list):
            raise ParseError("a Tenable vulnerability export chunk is a JSON array")
        for i, rec in enumerate(records):
            yield self._record(rec, pointer(i))
        # One chunk is a slice of an export: it never proves absence of anything else.
        yield ScanSummary(tool="tenable_vm", tool_version=None, complete=None,
                          completeness_reason="export chunk; completeness is decided at export level",
                          supports_absence_inference=False)

    @staticmethod
    def _record(rec: Any, loc: str) -> ParseEvent:
        if not isinstance(rec, dict):
            return Quarantine(loc, "not_an_object", "chunk entry is not an object", stable_digest(rec))
        asset, plugin, port = rec.get("asset") or {}, rec.get("plugin") or {}, rec.get("port") or {}
        asset_uuid = asset.get("uuid")
        if not isinstance(asset_uuid, str) or not asset_uuid:
            return Quarantine(loc, "missing_asset_uuid", "asset.uuid is required for a stable asset identity",
                              stable_digest(rec))
        plugin_id = plugin.get("id")
        if not isinstance(plugin_id, int):
            return Quarantine(loc, "missing_plugin_id", "plugin.id is required", stable_digest(rec))
        state = rec.get("state")
        if state not in _STATES:
            return Quarantine(loc, "invalid_state", f"state {state!r} not in OPEN, REOPENED, FIXED", stable_digest(rec))
        severity = rec.get("severity")
        if severity is not None and severity not in _SEVERITIES:
            return Quarantine(loc, "invalid_severity", f"unexpected severity {severity!r}", stable_digest(rec))
        idents = [Identifier("tenable_asset_uuid", asset_uuid)]
        for ns, key in (("hostname", "hostname"), ("fqdn", "fqdn"), ("ipv4", "ipv4"), ("ipv6", "ipv6"),
                        ("netbios_name", "netbios_name")):
            value = asset.get(key)
            for v in (value if isinstance(value, list) else [value]):
                if isinstance(v, str) and v:
                    idents.append(Identifier(ns, v.lower()))
        port_no, proto = port.get("port"), port.get("protocol")
        component = f"{proto or '?'}/{port_no if port_no is not None else '?'}"
        cves = plugin.get("cve") if isinstance(plugin.get("cve"), list) else []
        normalised = {"plugin_id": plugin_id, "plugin_name": plugin.get("name"), "cves": cves, "state": state,
                      "severity": severity, "port": port_no, "protocol": proto,
                      "first_found": rec.get("first_found"), "last_found": rec.get("last_found"),
                      "last_fixed": rec.get("last_fixed"), "finding_id": rec.get("finding_id")}
        return FindingRecord(
            locator=loc, external_id=f"{asset_uuid}|plugin:{plugin_id}|{component}",
            version_key=stable_digest({"state": state, "last_found": rec.get("last_found"),
                                       "last_fixed": rec.get("last_fixed"), "severity": severity}),
            subject=SubjectHints(identifiers=tuple(idents), kind="host",
                                 display_name=asset.get("hostname") or asset.get("fqdn") or asset_uuid),
            component_locator=component, vulnerability_ref=f"tenable-plugin:{plugin_id}",
            title=plugin.get("name") if isinstance(plugin.get("name"), str) else None, source_severity=severity,
            source_status=_STATES[state], source_time=parse_time(rec.get("last_fixed") or rec.get("last_found")),
            normalised=normalised, source_fields=rec)


# ---------------------------------------------------------------------------- API client
class TenableApiError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class ExportResult:
    export_uuid: str
    status: str
    chunks: list[int]
    failed_chunks: list[int]
    cancelled_chunks: list[int]


class TenableExportClient:
    """Minimal client for the vulnerability export workflow.

    Credentials come from a callable so secrets never live in configuration rows. Retries are bounded;
    429 honours `retry-after`. Timeouts and 5xx are retryable; 4xx (except 409/429) are not.
    """

    def __init__(self, base_url: str, credentials: Callable[[], tuple[str, str]], *,
                 transport: httpx.BaseTransport | None = None, max_attempts: int = 5,
                 sleep: Callable[[float], None] = time.sleep, poll_interval: float = 5.0, max_polls: int = 720):
        self._base = base_url.rstrip("/")
        self._credentials = credentials
        self._client = httpx.Client(transport=transport, timeout=httpx.Timeout(60.0, connect=10.0))
        self._max_attempts = max_attempts
        self._sleep = sleep
        self._poll_interval = poll_interval
        self._max_polls = max_polls

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        access, secret = self._credentials()
        headers = {"X-ApiKeys": f"accessKey={access};secretKey={secret}", "Accept": "application/json"}
        for attempt in range(1, self._max_attempts + 1):
            try:
                resp = self._client.request(method, self._base + path, headers=headers, **kwargs)
            except httpx.TransportError as exc:
                if attempt == self._max_attempts:
                    raise TenableApiError(f"transport error: {type(exc).__name__}", retryable=True) from exc
                self._sleep(min(60.0, 2.0 ** attempt))
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == self._max_attempts:
                    raise TenableApiError(f"HTTP {resp.status_code} after {attempt} attempts", retryable=True)
                retry_after = resp.headers.get("retry-after")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(60.0, 2.0 ** attempt)
                self._sleep(min(delay, 300.0))
                continue
            return resp
        raise AssertionError("unreachable")

    def request_export(self, *, filters: dict, num_assets: int = 500) -> str:
        resp = self._request("POST", "/vulns/export", json={"num_assets": num_assets, "filters": filters})
        if resp.status_code == 409:
            body = resp.json()
            if isinstance(body, dict) and body.get("active_job_id"):
                return body["active_job_id"]     # adopt the identical export that is already running
            raise TenableApiError("export conflict without active_job_id", retryable=False)
        if resp.status_code != 200:
            raise TenableApiError(f"export request failed: HTTP {resp.status_code}", retryable=False)
        return resp.json()["export_uuid"]

    def wait_for_export(self, export_uuid: str) -> ExportResult:
        for _ in range(self._max_polls):
            resp = self._request("GET", f"/vulns/export/{export_uuid}/status")
            if resp.status_code != 200:
                raise TenableApiError(f"status failed: HTTP {resp.status_code}", retryable=resp.status_code != 404)
            body = resp.json()
            status = body.get("status")
            if status in ("FINISHED", "CANCELLED", "ERROR"):
                return ExportResult(export_uuid, status, sorted(body.get("chunks_available") or []),
                                    sorted(body.get("chunks_failed") or []), sorted(body.get("chunks_cancelled") or []))
            if status not in ("QUEUED", "PROCESSING"):
                raise TenableApiError(f"unknown export status {status!r}", retryable=False)
            self._sleep(self._poll_interval)
        raise TenableApiError("export did not finish within the polling budget", retryable=True)

    def download_chunk(self, export_uuid: str, chunk_id: int) -> bytes:
        resp = self._request("GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}")
        if resp.status_code == 404:
            raise TenableApiError(f"chunk {chunk_id} not found or expired", retryable=False)
        if resp.status_code != 200:
            raise TenableApiError(f"chunk download failed: HTTP {resp.status_code}", retryable=False)
        return resp.content
