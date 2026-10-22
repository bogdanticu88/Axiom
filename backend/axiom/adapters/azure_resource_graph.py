"""Azure Resource Graph context adapter: resources -> assets with identity and asserted business context.

References checked 2026-10-22 (learn.microsoft.com): POST
https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01 with
{query, subscriptions, options:{$top (1..1000), $skipToken, resultFormat}}; response {totalRecords, count,
resultTruncated, $skipToken, data}; throttling headers x-ms-user-quota-remaining and
x-ms-user-quota-resets-after (hh:mm:ss); each page consumes quota.

Tags are owner assertions, not independent observations: context from tags is recorded with basis
'source_tag_assertion'. Support level: fixture-tested with SYNTHETIC pages and a local fake API; never run
against a live Azure subscription.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from .base import (AdapterInfo, AssetRecord, Identifier, ParseError, ParseEvent, Quarantine, ScanSummary,
                   SubjectHints, SupportLevel, load_json, pointer, stable_digest)

API_VERSION = "2024-04-01"
DEFAULT_QUERY = ("Resources | where type in~ ('microsoft.compute/virtualmachines', "
                 "'microsoft.containerregistry/registries', 'microsoft.containerservice/managedclusters', "
                 "'microsoft.web/sites') | project id, name, type, location, subscriptionId, resourceGroup, tags, "
                 "properties")

INFO = AdapterInfo(
    name="azure_resource_graph", version="1.0.0", adapter_kind="context", formats=("arg-objectArray-page",),
    operations=("api_sync",), support_level=SupportLevel.FIXTURE_TESTED,
    validation_notes="Synthetic pages and a local fake API only. Requires an Azure subscription and a service "
                     "principal or workload identity with Reader for sandbox validation.")

_KINDS = {"microsoft.compute/virtualmachines": "host", "microsoft.containerservice/managedclusters": "cloud_resource",
          "microsoft.web/sites": "application"}
_CRITICALITY = {"low", "medium", "high", "critical"}


class ResourceGraphPageParser:
    info = INFO

    def parse(self, data: bytes, *, declared_subject: SubjectHints | None = None) -> Iterator[ParseEvent]:
        page = load_json(data)
        if not isinstance(page, dict) or not isinstance(page.get("data"), list):
            raise ParseError("expected an Azure Resource Graph response with an objectArray 'data' list")
        for i, row in enumerate(page["data"]):
            yield self._row(row, pointer("data", i))
        yield ScanSummary(tool="azure_resource_graph", tool_version=API_VERSION, complete=None,
                          completeness_reason="single page; completeness decided by the sync",
                          supports_absence_inference=False)

    @staticmethod
    def _row(row: Any, loc: str) -> ParseEvent:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].startswith("/subscriptions/"):
            return Quarantine(loc, "missing_resource_id", "row lacks an Azure resource id", stable_digest(row))
        rid = row["id"].lower()            # Azure resource IDs are case-insensitive
        rtype = (row.get("type") or "").lower()
        idents = [Identifier("azure_resource_id", rid)]
        props = row.get("properties") if isinstance(row.get("properties"), dict) else {}
        if isinstance(props.get("vmId"), str):
            idents.append(Identifier("azure_vm_id", props["vmId"].lower()))
        computer = ((props.get("osProfile") or {}).get("computerName") if isinstance(props.get("osProfile"), dict)
                    else None)
        if isinstance(computer, str) and computer:
            idents.append(Identifier("hostname", computer.lower()))
        tags = row.get("tags") if isinstance(row.get("tags"), dict) else {}
        criticality = str(tags.get("criticality", "")).lower() or None
        context = {"owner_ref": tags.get("owner"), "environment": tags.get("env") or tags.get("environment"),
                   "criticality": criticality if criticality in _CRITICALITY else None,
                   "location": row.get("location"), "tags": tags, "resource_type": rtype}
        return AssetRecord(
            locator=loc, external_id=rid,
            version_key=stable_digest({"tags": tags, "location": row.get("location"), "type": rtype}),
            subject=SubjectHints(identifiers=tuple(idents), kind=_KINDS.get(rtype, "cloud_resource"),
                                 display_name=row.get("name") or rid),
            context=context, source_time=None, source_fields=row)


class ResourceGraphClient:
    """Pages through a Resource Graph query. Token acquisition is injected (workload identity in production)."""

    def __init__(self, token: Callable[[], str], *, base_url: str = "https://management.azure.com",
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep,
                 max_attempts: int = 5):
        self._token = token
        self._base = base_url.rstrip("/")
        self._client = httpx.Client(transport=transport, timeout=httpx.Timeout(60.0, connect=10.0))
        self._sleep = sleep
        self._max_attempts = max_attempts

    @staticmethod
    def _reset_seconds(value: str | None) -> float:
        try:
            h, m, s = (value or "").split(":")
            return int(h) * 3600 + int(m) * 60 + float(s)
        except ValueError:
            return 5.0

    def pages(self, *, subscriptions: list[str], query: str = DEFAULT_QUERY, page_size: int = 1000,
              skip_token: str | None = None) -> Iterator[tuple[bytes, str | None]]:
        """Yield (raw page bytes, next skip token). Resume by passing the last stored skip token."""
        url = f"{self._base}/providers/Microsoft.ResourceGraph/resources?api-version={API_VERSION}"
        token = skip_token
        while True:
            options: dict[str, Any] = {"$top": page_size, "resultFormat": "objectArray"}
            if token:
                options["$skipToken"] = token
            body = {"query": query, "subscriptions": subscriptions, "options": options}
            for attempt in range(1, self._max_attempts + 1):
                resp = self._client.post(url, json=body, headers={"Authorization": f"Bearer {self._token()}"})
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt == self._max_attempts:
                        raise RuntimeError(f"Resource Graph HTTP {resp.status_code} after {attempt} attempts")
                    retry = resp.headers.get("retry-after")
                    wait = float(retry) if retry and retry.isdigit() else self._reset_seconds(
                        resp.headers.get("x-ms-user-quota-resets-after"))
                    self._sleep(wait + random.uniform(0, 1))
                    continue
                if resp.status_code != 200:
                    raise RuntimeError(f"Resource Graph HTTP {resp.status_code}")
                break
            payload = resp.json()
            token = payload.get("$skipToken")
            yield resp.content, token
            if resp.headers.get("x-ms-user-quota-remaining") == "0":
                self._sleep(self._reset_seconds(resp.headers.get("x-ms-user-quota-resets-after")))
            if not token:
                return
