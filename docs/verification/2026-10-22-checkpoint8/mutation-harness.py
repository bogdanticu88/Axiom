"""Checkpoint-8 mutation checks. For each mutation: the weakened control, the security property it should break, the
tests meant to catch it, and (from the run) which tests failed and the first assertion line of each failure.
Bytecode is never written, caches are purged around each run, restored files are compared byte for byte, and every
targeted test runs once more on the restored tree.

    python3 mutate8.py [ID ...] > log        (from the repository root)
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DIB = "tests/integration/test_database_identity_boundary.py"
RVB = "tests/integration/test_revocation_boundary.py"
VDST = "tests/integration/test_verification_destinations.py"
VLC = "tests/integration/test_verification_lifecycle.py"
VCU = "tests/unit/test_verification_checks.py"
TLS = "tests/integration/test_tls_deployment.py"
CHK = "backend/axiom/verification/checks.py"
WRK = "backend/axiom/verification/worker.py"

M = [
    # id, control weakened, property, file, old, new, targets
    ("I1", "authority bindings no longer share-locked", "a revocation waits for a command that already checked",
     "backend/axiom/access.py", " FOR SHARE OF b, m", "",
     [f"{RVB}::test_a_command_that_fails_after_its_check_releases_the_lock_and_commits_nothing",
      f"{RVB}::test_shortening_a_membership_waits_like_a_suspension"]),
    ("I2", "bind_context accepts a second principal", "one principal per transaction through bind_context",
     "backend/axiom/migrations/0017_authority_hardening.sql",
     "  IF existing_principal IS NOT NULL AND existing_principal <> p_principal THEN", "  IF false THEN",
     [f"{DIB}::test_context_ends_with_the_transaction_after_commit_rollback_and_failure",
      f"{DIB}::test_the_no_switch_rule_is_enforced_by_bind_context_only"]),
    ("I3", "context no longer tied to its transaction", "context ends with the transaction (pool safety)",
     "backend/axiom/migrations/0001_foundation.sql",
     "  SELECT CASE WHEN split_part(c, '|', 3) = axiom.tx_marker()", "  SELECT CASE WHEN true",
     [f"{DIB}::test_context_ends_with_the_transaction_after_commit_rollback_and_failure",
      "tests/integration/test_isolation.py::test_session_level_context_does_not_leak_into_next_transaction"]),
    ("I4", "decisions no longer append-only", "the runtime credential cannot rewrite history",
     "backend/axiom/migrations/0002_cases.sql",
     "CREATE TRIGGER decisions_append_only BEFORE UPDATE OR DELETE ON axiom.decisions\n  FOR EACH ROW",
     "CREATE TRIGGER decisions_append_only BEFORE UPDATE OR DELETE ON axiom.decisions\n  FOR EACH ROW WHEN (false)",
     [f"{DIB}::test_recorded_history_cannot_be_rewritten_with_the_runtime_credential",
      "tests/integration/test_isolation.py::test_append_only_tables_reject_mutation_even_for_owner"]),
    ("W1", "destination allowlist ignored", "only operator-allowed origins are contacted",
     CHK, "        if _normal_origin(base_url) not in self.origins:", "        if False:",
     [f"{VDST}::test_an_unapproved_destination_is_never_contacted", f"{VCU}::test_refused_origins"]),
    ("W2", "resolved addresses not checked", "loopback, metadata and out-of-network addresses are not contacted",
     CHK, "        for a in addresses:\n            ip = ipaddress.ip_address(a)", "        for a in []:\n            ip = ipaddress.ip_address(a)",
     [f"{VDST}::test_resolved_addresses_must_be_allowed", f"{VDST}::test_an_address_change_between_attempts_is_checked_again"]),
    ("W3", "connection not pinned to the checked address", "the request goes to the address that was checked",
     CHK, '        url = f"https://{literal}:{port}{parts.path}/v1/checks"',
     '        url = f"https://{host}:{port}{parts.path}/v1/checks"',
     [f"{VDST}::test_the_validated_address_is_the_address_contacted"]),
    ("W3b", "TLS checked against the address instead of the configured name",
     "TLS validates the configured hostname while connecting to the validated address",
     CHK, ',\n                              extensions={"sni_hostname": host}) as r:', ') as r:',
     [f"{VDST}::test_the_validated_address_is_the_address_contacted"]),
    ("W4", "TLS failures treated as transient", "an untrusted certificate parks the job instead of retrying",
     CHK, "            if _tls_failure(exc):", "            if False:",
     [f"{VDST}::test_tls_failures_park_the_job_without_sending_the_request"]),
    ("W5", "nonce not checked", "a response must be bound to this attempt",
     CHK, 'doc.get("nonce") != nonce or ', "",
     [f"{VCU}::test_rules", f"{VDST}::test_oversized_generic_or_unbound_responses_do_not_verify"]),
    ("W6", "echoed credential stored", "the credential never reaches stored evidence",
     CHK, "        if token and token.encode() in data:", "        if False:",
     [f"{VDST}::test_an_echoed_credential_is_redacted_and_never_stored_or_logged"]),
    ("W7", "redirects followed", "a redirect target receives nothing",
     CHK, "follow_redirects=False, trust_env=False", "follow_redirects=True, trust_env=False",
     [f"{VDST}::test_a_redirect_is_not_followed_and_its_target_receives_nothing"]),
    ("W8", "report-level duplicate check removed", "a second job for a verified report does not call or record",
     WRK, '        if conn.execute("SELECT 1 FROM axiom.verification_runs WHERE remediation_report_id = %s",',
     '        if False and conn.execute("SELECT 1 FROM axiom.verification_runs WHERE remediation_report_id = %s",',
     [f"{VLC}::test_a_second_job_for_an_already_verified_report_is_skipped"]),
    ("W9", "one observation per job not enforced", "the database refuses a second observation for a job",
     "backend/axiom/migrations/0018_verification_worker.sql", "  UNIQUE (tenant_id, job_id),\n", "",
     [f"{VLC}::test_the_database_refuses_a_second_observation_for_a_job"]),
    ("T1", "session cookie not Secure", "session cookies only travel over TLS",
     "backend/axiom/api/app.py", "secure=settings.ui_cookie_secure, samesite", "secure=False, samesite",
     [f"{TLS}::test_browser_sign_in_over_tls_with_secure_cookies_csrf_logout_and_replay",
      f"{TLS}::test_callback_and_logout_redirects_use_the_configured_origin"]),
    ("T2", "sign-in redirect built from request headers", "redirects use the configured external origin",
     "backend/axiom/api/app.py",
     '    def login(return_to: str | None = None):\n        if sessions is None:\n            raise NotFound("sign-in is not configured", code="sso_not_configured")\n        url, binding = sessions.start_login(return_to)',
     '    def login(request: Request, return_to: str | None = None):\n        if sessions is None:\n            raise NotFound("sign-in is not configured", code="sso_not_configured")\n        url, binding = sessions.start_login(return_to)\n        from urllib.parse import quote\n        host = request.headers.get("x-forwarded-host") or request.headers.get("host")\n        url = url.replace(quote(settings.oidc_redirect_uri, safe=""), quote(f"https://{host}/auth/callback", safe=""))',
     [f"{TLS}::test_spoofed_forwarding_and_host_headers_do_not_change_redirects"]),
    ("T3", "CSRF check skipped", "unsafe session requests need the CSRF token",
     "backend/axiom/auth/sessions.py", "        if method.upper() in UNSAFE and (not csrf_header", "        if False and (not csrf_header",
     [f"{TLS}::test_browser_sign_in_over_tls_with_secure_cookies_csrf_logout_and_replay"]),
    ("T4", "logout does not revoke the session", "a logged-out session cookie is refused",
     "backend/axiom/auth/sessions.py", "        if token:\n            with self.db.unbound_tx() as conn:\n                conn.execute(\"SELECT axiom_auth.session_revoke(%s, 'logout')\", (h(token),))",
     "        if False:\n            pass",
     [f"{TLS}::test_browser_sign_in_over_tls_with_secure_cookies_csrf_logout_and_replay",
      f"{TLS}::test_callback_and_logout_redirects_use_the_configured_origin"]),
    ("T5", "secret error quotes the file", "secret-file failures do not reveal contents",
     "backend/axiom/secretrefs.py", '            raise ConfigurationError("secret file is too large")',
     '            raise ConfigurationError("secret file is too large: " + real.read_text()[:60])',
     [f"{TLS}::test_secret_file_failures_stop_start_up_without_revealing_contents"]),
]


def purge():
    for base in ("backend", "tests", "scripts", "evaluation"):
        for p in Path(base).rglob("__pycache__"):
            shutil.rmtree(p, ignore_errors=True)


def run(targets):
    env = dict(os.environ, AXIOM_REQUIRE_UI="1", PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run(["uv", "run", "--frozen", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short", *targets],
                       capture_output=True, text=True, env=env, timeout=1800)
    return r.returncode, (r.stdout.strip().splitlines() or [""])[-1], r.stdout


def first_assertions(out):
    """Map each failing test to the first 'E ' line of its traceback section."""
    found, current = {}, None
    for line in out.splitlines():
        m = re.match(r"^_+ (\S+) _+$", line)
        if m:
            current = m.group(1)
            continue
        if current and line.startswith("E ") and current not in found:
            found[current] = line[1:].strip()[:220]
    return found


def main():
    only = set(sys.argv[1:])
    for mid, control, prop, path, old, new, targets in M:
        if only and mid not in only:
            continue
        original = Path(path).read_bytes()
        assert original.decode().count(old) == 1, (mid, "mutation point not unique or missing")
        purge()
        try:
            Path(path).write_text(original.decode().replace(old, new, 1))
            rc, tail, out = run(targets)
        finally:
            Path(path).write_bytes(original)
            purge()
        assert hashlib.sha256(Path(path).read_bytes()).digest() == hashlib.sha256(original).digest()
        print(f"{mid} weakened: {control}\n   property: {prop}\n   verdict: {'CAUGHT' if rc else 'SURVIVED'} ({tail})",
              flush=True)
        for test, line in first_assertions(out).items():
            print(f"   failed: {test}\n      first assertion: {line}", flush=True)
    all_targets = sorted({t for m in M for t in m[6] if not only or m[0] in only})
    rc, tail, _ = run(all_targets)
    print(f"sanity: all targeted tests on the restored tree: rc={rc} ({tail})")


if __name__ == "__main__":
    main()
