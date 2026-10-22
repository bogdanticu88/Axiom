"""Checkpoint-6 mutation checks: weaken one new control at a time, run the tests meant to catch it, restore.

Safer than the checkpoint-5 harness: bytecode is never written (PYTHONDONTWRITEBYTECODE=1), every __pycache__ under
backend/ and tests/ is purged before and after each mutation, the restored file is compared byte-for-byte with the
original, and after all mutations every targeted test runs once more on the restored tree.

    python3 mutate6.py [ID ...] > log        (from the repository root)
"""
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

T_AUTH = "tests/integration/test_system_authority_boundary.py"
T_OVR = "tests/integration/test_authority_and_overrides.py"
T_SSO = "tests/integration/test_oidc_sso.py"
T_OIDCU = "tests/unit/test_oidc_validation.py"
T_UIW = "tests/integration/test_analyst_ui_workflows.py"
MIG = "backend/axiom/migrations/0016_system_authority_checks.sql"

M = [
    ("N1", "database trusts any workload permission (holds_permission ignored)", MIG,
     "allowed := COALESCE(axiom.holds_permission(actor, needed, case_scope), false);", "allowed := true;",
     [f"{T_AUTH}::test_workload_bound_to_one_project_cannot_act_on_another",
      f"{T_AUTH}::test_revoked_system_binding_stops_policy_results",
      f"{T_OVR}::test_system_principal_records_only_policy_authorised_results"]),
    ("N2", "workload may reopen for any reason", MIG,
     "WHEN NEW.kind = 'reopen' AND NEW.outcome IN ('recurrence', 'acceptance_expiry') THEN 'case.reopen'",
     "WHEN NEW.kind = 'reopen' THEN 'case.reopen'",
     [f"{T_OVR}::test_system_principal_records_only_policy_authorised_results",
      f"{T_AUTH}::test_database_refuses_discretionary_decisions_by_the_system_even_with_forged_authority"]),
    ("N3", "role-binding kind guard disabled", MIG,
     "IF holder IS DISTINCT FROM allowed_kind THEN", "IF false THEN",
     [f"{T_AUTH}::test_system_principal_cannot_be_given_a_human_role"]),
    ("N4", "audit records the in-process context's kind", "backend/axiom/audit.py",
     "COALESCE(axiom_auth.principal_kind(%s), %s)", "COALESCE(NULL::text || %s::text, %s)",
     [f"{T_AUTH}::test_decisions_record_the_kind_from_identity_records"]),
    ("N5", "PKCE verifier not sent in the code exchange", "backend/axiom/auth/oidc.py",
     '"code_verifier": code_verifier},', "},",
     [f"{T_OIDCU}::test_code_exchange_sends_pkce_verifier_and_basic_client_authentication",
      f"{T_SSO}::test_login_creates_a_session_and_tenant_access_is_checked_per_request"]),
    ("N6", "token endpoint errors accepted", "backend/axiom/auth/oidc.py",
     "        if r.status_code != 200:\n            try:\n                reason",
     "        if False:\n            try:\n                reason",
     [f"{T_OIDCU}::test_failed_code_exchanges_refuse_the_login"]),
    ("N7", "client secret not resolved at start-up", "backend/axiom/api/app.py",
     "        EnvSecretResolver().resolve(secret_ref)      #", "        pass      #",
     [f"{T_SSO}::test_unresolvable_client_secret_stops_start_up"]),
    ("N8", "production UI allowed without sign-in", "backend/axiom/config.py",
     "if self.ui_dist_dir and not self.oidc_issuer:", "if False:",
     [f"{T_SSO}::test_production_sso_settings_are_checked"]),
    ("N9", "risk history shows the audit trail without audit.read", "backend/axiom/api/operations.py",
     'if authz.has("audit.read", root["id"]):', "if True:",
     [f"{T_UIW}::test_risk_acceptance_request_rules_expiry_and_history"]),
]


def purge():
    for base in ("backend", "tests", "scripts", "evaluation"):
        for p in Path(base).rglob("__pycache__"):
            shutil.rmtree(p, ignore_errors=True)


def run(targets):
    env = dict(os.environ, AXIOM_REQUIRE_UI="1", PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run(["uv", "run", "--frozen", "pytest", "-q", "-p", "no:cacheprovider", *targets],
                       capture_output=True, text=True, env=env, timeout=1500)
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    return r.returncode, tail, r.stdout


def main():
    only = set(sys.argv[1:])
    for mid, name, path, old, new, targets in M:
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
        failed = [l.split(" ")[1] for l in out.splitlines() if l.startswith("FAILED ")]
        verdict = "CAUGHT" if rc != 0 else "SURVIVED"
        print(f"{mid} {name}: {verdict} ({tail})", flush=True)
        for f in failed:
            print(f"     failed: {f}", flush=True)
    all_targets = sorted({t for m in M for t in m[5] if not only or m[0] in only})
    rc, tail, _ = run(all_targets)
    print(f"sanity: all targeted tests on the restored tree: rc={rc} ({tail})")


if __name__ == "__main__":
    main()
