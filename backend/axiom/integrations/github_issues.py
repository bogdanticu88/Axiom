"""GitHub Issues ticket integration. Support level: **fixture-tested** (local fake only). An opt-in test against
the real API is prepared (tests/integration/test_github_issues_optin.py, docs/integration-tests/github-issues.md) but
has not been run.

Shapes follow GitHub's public REST documentation (API version header ``2022-11-28``): ``POST
/repos/{owner}/{repo}/issues`` (``title``, ``body``, ``labels``) returns 201 with ``number``, ``state``,
``state_reason``; ``GET /repos/{owner}/{repo}/issues/{number}``; ``GET /repos/{owner}/{repo}/issues`` with
``state=all``, ``since``, ``per_page`` and ``page``.

Duplicate prevention: GitHub offers no idempotency key we could rely on, so ``dedupe='none'``. The operation key is
written as a marker line in the issue body (label-name limits are not documented on the labels page, so the 70-character
operation label used for Jira is not used here). Lookup scans recently updated issues for that marker; its
consistency after a lost acknowledgement is not documented, so it is treated as eventual: a hit is adopted, a miss
after an uncertain create parks for reconciliation. The scan is bounded (``max_pages``), another reason a miss is
never proof.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..jobs.effects import DefinitelyNotApplied, PermanentFailure, UnknownOutcome

MARKER = "axiom-operation: "


class GitHubIssueAdapter:
    integration = "github_issues"
    dedupe, lookup, provider_fencing = "none", "eventual", False

    def __init__(self, repo: str, token, *, api: str = "https://api.github.com", transport=None, max_pages: int = 5,
                 lookback_hours: int = 72):
        if "/" not in repo:
            raise ValueError("repo must be owner/name")
        self.repo, self.token, self.api = repo, token, api.rstrip("/")
        self.max_pages, self.lookback = max_pages, timedelta(hours=lookback_hours)
        self.http = httpx.Client(transport=transport, timeout=20.0)

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token()}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def _ref(self, number: int) -> str:
        return f"{self.repo}#{number}"

    def _number(self, ref: str) -> int:
        repo, _, n = ref.partition("#")
        if repo != self.repo:
            raise ValueError("reference belongs to another repository")
        return int(n)

    def find(self, operation_key: str) -> str | None:
        since = (datetime.now(timezone.utc) - self.lookback).strftime("%Y-%m-%dT%H:%M:%SZ")
        marker = MARKER + operation_key
        for page in range(1, self.max_pages + 1):
            r = self.http.get(f"{self.api}/repos/{self.repo}/issues", headers=self._headers(),
                              params={"state": "all", "since": since, "per_page": 100, "page": page})
            r.raise_for_status()
            items = r.json()
            for issue in items:
                if marker in (issue.get("body") or "").splitlines():
                    return self._ref(issue["number"])
            if len(items) < 100:
                return None
        return None

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str:
        body = f"{request.get('description', '')}\n\n{MARKER}{operation_key}".lstrip()
        try:
            headers = self._headers()
        except Exception as exc:  # noqa: BLE001 - the credential could not be read, so no request was sent
            raise DefinitelyNotApplied(f"credential unavailable: {type(exc).__name__}") from exc
        try:
            r = self.http.post(f"{self.api}/repos/{self.repo}/issues", headers=headers,
                               json={"title": request["summary"], "body": body, "labels": request.get("labels", [])})
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise DefinitelyNotApplied(f"{type(exc).__name__}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise UnknownOutcome(f"{type(exc).__name__}: {exc}") from exc
        if r.status_code == 201:
            return self._ref(r.json()["number"])
        if r.status_code in (401, 404, 410, 422):
            raise PermanentFailure(f"{r.status_code}: {r.text[:300]}")
        raise UnknownOutcome(f"HTTP {r.status_code}")       # 403/429 rate limits and 5xx: outcome not guaranteed

    def _issue(self, ref: str) -> dict | None:
        r = self.http.get(f"{self.api}/repos/{self.repo}/issues/{self._number(ref)}", headers=self._headers())
        if r.status_code in (404, 410):
            return None
        r.raise_for_status()
        return r.json()

    def verify(self, ref: str, operation_key: str) -> bool | None:
        try:
            issue = self._issue(ref)
        except httpx.HTTPError:
            return None
        return issue is not None and (MARKER + operation_key) in (issue.get("body") or "").splitlines()

    def fetch_state(self, ref: str) -> tuple[str, str]:
        issue = self._issue(ref)
        if issue is None:
            return "missing", "missing"
        if issue.get("state") == "closed":
            return f"closed:{issue.get('state_reason') or 'unknown'}", "done"
        return "open", "open"
