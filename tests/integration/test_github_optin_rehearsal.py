"""The opt-in GitHub Issues test, rehearsed against the local fake with real network blocked (no credentials).

Each case runs ``test_github_issues_optin.py`` in a child pytest process with ``github_optin_rehearsal`` loaded: it
blocks real HTTP before any fixture exists and points the test at the non-routable ``api.github.test.invalid`` and
the example repository ``example-owner/axiom-optin-rehearsal``. This guards the test's own logic and the guarantee
that a rehearsal cannot reach GitHub; it says nothing about GitHub's behaviour.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.db
ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_REPO = "example-owner/axiom-optin-rehearsal"
FAKE_TOKEN = "rehearsal-placeholder-not-a-credential"


def child(tmp_path, *, enabled=True, mode="normal", late_fake=False, approved=EXAMPLE_REPO):
    token = tmp_path / "secrets" / "token"
    token.parent.mkdir(mode=0o700)
    token.write_text(FAKE_TOKEN + "\n")
    token.chmod(0o600)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AXIOM_TEST_GITHUB", "REHEARSAL_"))}
    env.update(PYTHONPATH=str(ROOT / "tests"), REHEARSAL_LATE_FAKE="1" if late_fake else "0")
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        env.pop(k, None)
    if enabled:
        env.update(AXIOM_TEST_GITHUB_ISSUES="1", AXIOM_TEST_GITHUB_REPO=EXAMPLE_REPO,
                   AXIOM_TEST_GITHUB_APPROVED_REPO=approved, AXIOM_TEST_GITHUB_TOKEN_FILE=str(token),
                   AXIOM_TEST_GITHUB_MODE=mode)
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-s", "-p", "no:cacheprovider",
                        "-p", "integration.github_optin_rehearsal",
                        str(ROOT / "tests/integration/test_github_issues_optin.py")],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
    out = r.stdout + r.stderr
    attempts = int(re.search(r"REAL_NETWORK_ATTEMPTS (\d+)", out).group(1))
    assert FAKE_TOKEN not in out, "the placeholder token appeared in the child's output"
    return r.returncode, out, attempts


def summary(out: str) -> str:
    return [line for line in out.splitlines() if re.search(r"\d+ (passed|failed|skipped|error)", line)][-1]


def test_without_opt_in_the_module_is_skipped_and_sends_nothing(tmp_path):
    code, out, attempts = child(tmp_path, enabled=False)
    assert (code, attempts) == (0, 0) and "8 skipped" in summary(out)


@pytest.mark.parametrize("mode,expected", [("normal", "6 passed, 2 skipped"), ("readonly", "1 passed, 7 skipped"),
                                           ("revoked", "1 passed, 7 skipped")])
def test_rehearsal_passes_without_reaching_the_network(tmp_path, mode, expected):
    code, out, attempts = child(tmp_path, mode=mode)
    assert (code, attempts) == (0, 0), out[-3000:]
    assert expected in summary(out)
    if mode == "normal":
        assert "REHEARSAL_FAKE_ISSUES created=4 closed=4" in out


def test_unapproved_target_is_refused_before_any_request(tmp_path):
    code, out, attempts = child(tmp_path, approved="example-owner/some-other-repository")
    assert code != 0 and attempts == 0
    assert "must equal AXIOM_TEST_GITHUB_APPROVED_REPO" in out


def test_control_a_fake_installed_too_late_is_caught_by_the_network_block(tmp_path):
    """The original rehearsal mistake: the module's precondition check ran before the fake was installed. The
    block must refuse that request, and the child must fail."""
    code, out, attempts = child(tmp_path, late_fake=True)
    assert code != 0 and attempts > 0
    assert "rehearsal tried to reach the network" in out
