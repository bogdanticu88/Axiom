"""Jira-style ticket integration. Support level: **fixture-tested** (local fake only).

The request and response shapes follow Atlassian's public Jira Cloud REST v3 documentation as read on 2026-10-22:
``POST /rest/api/3/issue`` (fields: project.key, summary, issuetype.name, labels, description as an Atlassian
Document Format document; response ``id``, ``key``, ``self``), ``POST /rest/api/3/search/jql`` (body ``jql``,
``fields``, ``maxResults``; response ``issues``) and ``GET /rest/api/3/issue/{key}``. Nothing here has been run
against a real Jira site. This is not a claim of Jira support.

Capabilities that matter for duplicate prevention (ADR 0010):

* **No provider idempotency key and no uniqueness constraint** we could rely on, so ``dedupe = 'none'``.
* **Lookup is eventually consistent.** Atlassian's "search and reconcile" guidance states the JQL search API does
  not provide read-after-write consistency by default; ``reconcileIssues`` gives consistency only for issue IDs
  the caller already knows, which is exactly what a lost acknowledgement does not give us. So a lookup *miss* after
  an uncertain create proves nothing, and the effect gate parks the job for reconciliation instead of creating
  again. A lookup *hit* (an issue carrying our operation label) is adopted.
* **No fencing tokens.**

``TrackerCapabilities`` lets tests exercise the gate against a fake that *does* deduplicate or fence. Those modes
model hypothetical providers; they are not Jira behaviour and are never selected for a ``jira_style`` connection.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ..jobs.effects import AlreadyExists, DefinitelyNotApplied, PermanentFailure, UnknownOutcome

LABEL_PREFIX = "axiom-op-"


@dataclass(frozen=True)
class TrackerCapabilities:
    dedupe: str = "none"            # 'none' | 'idempotency_key' | 'unique_external_id'
    lookup: str = "eventual"        # 'none' | 'strong' | 'eventual'
    provider_fencing: bool = False


JIRA_CLOUD = TrackerCapabilities()   # what we rely on for a jira_style connection


def operation_label(operation_key: str) -> str:
    return f"{LABEL_PREFIX}{operation_key}"


def adf(text: str) -> dict:
    """Minimal Atlassian Document Format document holding plain text paragraphs."""
    paragraphs = [p for p in text.split("\n\n") if p.strip()] or [""]
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": p}] if p else []} for p in paragraphs]}


class JiraStyleClient:
    def __init__(self, base_url: str, auth: Callable[[], tuple[str, str]], *, transport: httpx.BaseTransport | None
                 = None, timeout: float = 20.0):
        if not base_url.startswith("https://"):
            raise ValueError("Jira-style connections must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self._auth = auth
        self._http = httpx.Client(transport=transport, timeout=timeout)

    def _headers(self, extra: dict | None = None) -> dict:
        user, token = self._auth()
        import base64
        basic = base64.b64encode(f"{user}:{token}".encode()).decode()
        return {"Authorization": f"Basic {basic}", "Accept": "application/json", **(extra or {})}

    def create_issue(self, fields: dict, *, extra_headers: dict | None = None) -> httpx.Response:
        return self._http.post(f"{self.base_url}/rest/api/3/issue", json={"fields": fields},
                               headers=self._headers(extra_headers))

    def search(self, jql: str, fields: list[str], max_results: int = 5) -> dict:
        r = self._http.post(f"{self.base_url}/rest/api/3/search/jql",
                            json={"jql": jql, "fields": fields, "maxResults": max_results}, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def get_issue(self, key: str, fields: list[str]) -> dict | None:
        r = self._http.get(f"{self.base_url}/rest/api/3/issue/{key}", params={"fields": ",".join(fields)},
                           headers=self._headers())
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


class JiraStyleTicketAdapter:
    """EffectAdapter for creating one ticket per operation key."""
    integration = "jira_style"

    def __init__(self, client: JiraStyleClient, capabilities: TrackerCapabilities = JIRA_CLOUD):
        self.client = client
        self.dedupe = capabilities.dedupe
        self.lookup = capabilities.lookup
        self.provider_fencing = capabilities.provider_fencing

    def find(self, operation_key: str) -> str | None:
        label = operation_label(operation_key)
        data = self.client.search(f'labels = "{label}" ORDER BY created ASC', ["labels"], max_results=5)
        for issue in data.get("issues", []):
            if label in (issue.get("fields", {}).get("labels") or []):
                return issue["key"]
        return None

    def verify(self, ref: str, operation_key: str) -> bool | None:
        """True if the issue exists and carries our operation label; False if it exists without it or is
        missing; None if the provider could not be reached (try again later)."""
        try:
            issue = self.client.get_issue(ref, ["labels"])
        except httpx.HTTPError:
            return None
        if issue is None:
            return False
        return operation_label(operation_key) in (issue.get("fields", {}).get("labels") or [])

    # Jira groups workflow statuses into the categories new / indeterminate / done (statusCategory.key).
    _CATEGORY = {"new": "open", "indeterminate": "in_progress", "done": "done"}

    def fetch_state(self, ref: str) -> tuple[str, str]:
        """(status name, category) for inbound synchronisation. Category 'missing' when the issue is gone.
        Raises httpx.HTTPError when the provider cannot be reached (try again later)."""
        issue = self.client.get_issue(ref, ["status"])
        if issue is None:
            return "missing", "missing"
        status = (issue.get("fields") or {}).get("status") or {}
        key = (status.get("statusCategory") or {}).get("key")
        return status.get("name", "unknown"), self._CATEGORY.get(key, "unknown")

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str:
        fields = {
            "project": {"key": request["project_key"]},
            "issuetype": {"name": request.get("issue_type", "Task")},
            "summary": request["summary"],
            "description": adf(request.get("description", "")),
            "labels": [operation_label(operation_key), *request.get("labels", [])],
        }
        extra = {}
        if self.dedupe == "idempotency_key":          # hypothetical provider capability, never Jira (see module doc)
            extra["Idempotency-Key"] = operation_key
        if self.provider_fencing:                     # hypothetical provider capability, never Jira
            extra["X-Fencing-Token"] = str(fencing_token)
        try:
            r = self.client.create_issue(fields, extra_headers=extra)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # no connection was established, so the request was never sent
            raise DefinitelyNotApplied(f"{type(exc).__name__}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise UnknownOutcome(f"{type(exc).__name__}: {exc}") from exc
        if r.status_code in (200, 201):
            return r.json()["key"]
        if r.status_code == 409 and self.provider_fencing and "stale fencing token" in r.text:
            raise DefinitelyNotApplied("provider rejected a stale fencing token")
        if r.status_code == 409 and self.dedupe == "unique_external_id":
            existing = (r.json() or {}).get("existing_key")
            if existing:
                raise AlreadyExists(existing)
            raise UnknownOutcome("409 without the existing object's key")
        if r.status_code in (400, 401, 403, 404):
            raise PermanentFailure(f"{r.status_code}: {r.text[:300]}")
        # 429 and 5xx: we have no documented guarantee that the request was not processed, so the outcome is
        # treated as unknown (conservative; revisit with sandbox validation).
        raise UnknownOutcome(f"HTTP {r.status_code}")
