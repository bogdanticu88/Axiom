"""Pytest plugin: run test_github_issues_optin.py against the local GitHub fake, never the network.

Loaded only by test_github_optin_rehearsal.py, in a child pytest process. Real HTTP transport is replaced at
configuration time, before any fixture exists, by one that records the attempt and refuses it; the API host is
replaced by the non-routable ``api.github.test.invalid``; the fake answers for the example repository named by the
child's environment. At the end the plugin prints ``REAL_NETWORK_ATTEMPTS <n>``.

``REHEARSAL_LATE_FAKE=1`` is a control that reproduces the original mistake (the fake installed by a function-scoped
fixture, after the module-scoped precondition check has run): that check then tries the real transport, and the
refusal must make the child fail.
"""
from __future__ import annotations

import os

import httpx
import pytest

ATTEMPTS: list[str] = []
REHEARSAL_API = "https://api.github.test.invalid"


def _refuse(self, request):
    ATTEMPTS.append(f"{request.method} {request.url.host}")
    raise AssertionError(f"rehearsal tried to reach the network: {request.method} {request.url.host}")


def pytest_configure(config):
    httpx.HTTPTransport.handle_request = _refuse


def pytest_unconfigure(config):
    print(f"\nREAL_NETWORK_ATTEMPTS {len(ATTEMPTS)}")


def _install(monkeypatch):
    import integration.test_github_issues_optin as m
    from integration.workflow_fakes import GitHubFake

    class Fake(GitHubFake):
        REPO = f"/repos/{m.REPO}/issues"
    fake = Fake()
    mode = os.environ.get("AXIOM_TEST_GITHUB_MODE")

    def handle(request):
        assert request.url.host == httpx.URL(REHEARSAL_API).host
        path = request.url.path
        if mode == "revoked":
            return httpx.Response(401, json={"message": "Bad credentials"})
        if mode == "readonly" and request.method == "POST":
            return httpx.Response(403, json={"message": "Resource not accessible by personal access token"},
                                  headers={"x-accepted-github-permissions": "issues=write"})
        if request.method == "GET" and path == f"/repos/{m.REPO}":
            return httpx.Response(200, json={"full_name": m.REPO, "private": True, "has_issues": True})
        if request.method == "PATCH" and path.startswith(fake.REPO + "/"):
            fake.close(int(path.rsplit("/", 1)[-1]), "not_planned")
            return httpx.Response(200, json={})
        return fake.handle(request)
    mock = httpx.MockTransport(handle)
    monkeypatch.setattr(m, "API", REHEARSAL_API)
    init = m.Recorder.__init__

    def recorder_init(self):
        init(self)
        self.inner = mock
    monkeypatch.setattr(m.Recorder, "__init__", recorder_init)

    def direct(method, path, **kw):
        with httpx.Client(transport=mock, follow_redirects=False) as c:
            return c.request(method, f"{REHEARSAL_API}{path}", headers={"X-GitHub-Api-Version": "2022-11-28"},
                             **kw)
    monkeypatch.setattr(m, "_direct", direct)
    return fake


if os.environ.get("REHEARSAL_LATE_FAKE") == "1":
    @pytest.fixture(autouse=True)
    def _fake_github_late(monkeypatch):
        yield _install(monkeypatch)
else:
    @pytest.fixture(scope="session", autouse=True)
    def _fake_github():
        monkeypatch = pytest.MonkeyPatch()
        fake = _install(monkeypatch)
        yield fake
        print(f"\nREHEARSAL_FAKE_ISSUES created={len(fake.records)} "
              f"closed={sum(1 for r in fake.records if r['state'] == 'closed')}")
        monkeypatch.undo()
