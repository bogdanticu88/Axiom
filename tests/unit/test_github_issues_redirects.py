"""The GitHub Issues adapter never follows a redirect, so its credential cannot be forwarded to another host."""
from __future__ import annotations

import httpx
import pytest

from axiom.integrations.github_issues import GitHubIssueAdapter
from axiom.jobs.effects import UnknownOutcome

API = "https://api.github.test.invalid"


def adapter(seen):
    def handle(request):
        seen.append((request.url.host, "authorization" in request.headers))
        return httpx.Response(301, headers={"Location": "https://elsewhere.test.invalid/repos/x/y/issues"})
    return GitHubIssueAdapter("example-owner/repo", lambda: "placeholder", api=API,
                              transport=httpx.MockTransport(handle))


def test_lookup_redirect_is_not_followed():
    seen = []
    with pytest.raises(httpx.HTTPStatusError):
        adapter(seen).find("k" * 64)
    assert seen == [("api.github.test.invalid", True)]


def test_create_redirect_is_not_followed_and_is_not_treated_as_created():
    seen = []
    with pytest.raises(UnknownOutcome):
        adapter(seen).create("k" * 64, {"summary": "s", "description": "d", "labels": []}, 1)
    assert seen == [("api.github.test.invalid", True)]


def test_client_does_not_follow_redirects():
    assert adapter([]).http.follow_redirects is False
