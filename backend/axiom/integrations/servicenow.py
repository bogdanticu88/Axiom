"""ServiceNow-style ticket integration (Table API). Support level: **fixture-tested** (local fake only).

Shapes follow ServiceNow's public Table API documentation as read on 2026-10-22: ``POST /api/now/table/{table}``
returns ``{"result": {...}}`` with ``sys_id`` (201); ``GET /api/now/table/{table}`` takes ``sysparm_query`` and
``sysparm_fields``; ``GET /api/now/table/{table}/{sys_id}`` returns one record or 404. That documentation says nothing
about idempotency or read-after-write consistency, so this adapter declares **no deduplication** and treats lookup
as no stronger than eventual: after an uncertain create the effect gate adopts a hit and otherwise parks.

Instance-specific assumptions, configurable per connection and to be verified on each instance before any support
claim: the table (default ``incident``), the field holding our operation key (default ``correlation_id``), and the
mapping of ``state`` values to categories (defaults follow the base-system incident states).
"""
from __future__ import annotations

from typing import Any

import httpx

from ..jobs.effects import DefinitelyNotApplied, PermanentFailure, UnknownOutcome

DEFAULT_STATES = {"1": "open", "2": "in_progress", "3": "in_progress", "6": "done", "7": "done", "8": "done"}


class ServiceNowTicketAdapter:
    integration = "servicenow"
    dedupe, lookup, provider_fencing = "none", "eventual", False

    def __init__(self, base_url: str, auth, *, table: str = "incident", correlation_field: str = "correlation_id",
                 states: dict | None = None, transport: httpx.BaseTransport | None = None):
        if not base_url.startswith("https://"):
            raise ValueError("ServiceNow connections must use HTTPS")
        self.base, self.auth, self.table, self.field = base_url.rstrip("/"), auth, table, correlation_field
        self.states = states or DEFAULT_STATES
        self.http = httpx.Client(transport=transport, timeout=20.0)

    def _url(self, suffix: str = "") -> str:
        return f"{self.base}/api/now/table/{self.table}{suffix}"

    def _get(self, url, params=None):
        return self.http.get(url, params=params, auth=self.auth(), headers={"Accept": "application/json"})

    def find(self, operation_key: str) -> str | None:
        r = self._get(self._url(), {"sysparm_query": f"{self.field}={operation_key}",
                                    "sysparm_fields": f"sys_id,number,{self.field}", "sysparm_limit": "2"})
        r.raise_for_status()
        for rec in r.json().get("result", []):
            if rec.get(self.field) == operation_key:
                return rec["sys_id"]
        return None

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str:
        body = {"short_description": request["summary"], "description": request.get("description", ""),
                self.field: operation_key}
        try:
            r = self.http.post(self._url(), json=body, auth=self.auth(),
                               headers={"Accept": "application/json", "Content-Type": "application/json"})
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise DefinitelyNotApplied(f"{type(exc).__name__}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise UnknownOutcome(f"{type(exc).__name__}: {exc}") from exc
        if r.status_code in (200, 201):
            return r.json()["result"]["sys_id"]
        if r.status_code in (400, 401, 403, 404):
            raise PermanentFailure(f"{r.status_code}: {r.text[:300]}")
        raise UnknownOutcome(f"HTTP {r.status_code}")      # 429 / 5xx: no documented guarantee of non-processing

    def _record(self, ref: str) -> dict | None:
        r = self._get(self._url(f"/{ref}"), {"sysparm_fields": f"sys_id,number,state,{self.field}"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()["result"]

    def verify(self, ref: str, operation_key: str) -> bool | None:
        try:
            rec = self._record(ref)
        except httpx.HTTPError:
            return None
        return rec is not None and rec.get(self.field) == operation_key

    def fetch_state(self, ref: str) -> tuple[str, str]:
        rec = self._record(ref)
        if rec is None:
            return "missing", "missing"
        state = str(rec.get("state", ""))
        return state, self.states.get(state, "unknown")
