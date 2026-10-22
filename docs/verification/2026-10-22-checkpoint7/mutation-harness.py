"""Checkpoint-7 mutation checks: weaken one new control at a time, run the tests meant to catch it, restore.

Safer than the checkpoint-5 harness: bytecode is never written (PYTHONDONTWRITEBYTECODE=1), every __pycache__ under
backend/ and tests/ is purged before and after each mutation, the restored file is compared byte-for-byte with the
original, and after all mutations every targeted test runs once more on the restored tree.

    python3 mutate7.py [ID ...] > log        (from the repository root)
"""
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

T_CP7 = "tests/integration/test_authority_review_cp7.py"
T_SSO = "tests/integration/test_oidc_sso.py"
T_OIDCU = "tests/unit/test_oidc_validation.py"
T_SREF = "tests/unit/test_secretrefs.py"
T_VW = "tests/integration/test_verification_worker.py"
T_VCU = "tests/unit/test_verification_checks.py"
M17 = "backend/axiom/migrations/0017_authority_hardening.sql"
M18 = "backend/axiom/migrations/0018_verification_worker.sql"
W = "backend/axiom/verification/worker.py"
C = "backend/axiom/verification/checks.py"

M = [
    # ---------------------------------------------------------------- authority boundary
    ("A1", "decision guard accepts an actor other than the bound principal", M17,
     "  IF actor IS DISTINCT FROM axiom.current_principal() THEN", "  IF false THEN",
     [f"{T_CP7}::test_d1_bound_transaction_cannot_record_a_decision_as_someone_else",
      f"{T_CP7}::test_d1_approvals_must_be_recorded_by_the_bound_principal"]),
    ("A2", "bind_context allows re-binding another principal", M17,
     "  IF existing_principal IS NOT NULL AND existing_principal <> p_principal THEN", "  IF false THEN",
     [f"{T_CP7}::test_d2_a_bound_transaction_cannot_switch_principal"]),
    ("A3", "bindings not share-locked until commit", "backend/axiom/access.py",
     " FOR SHARE OF b, m", "",
     [f"{T_CP7}::test_d3_revocation_waits_for_a_command_that_already_checked_the_permission",
      f"{T_VW}::test_a_revocation_racing_the_commit_waits_for_it"]),
    ("A4", "principal kind may change", M17,
     "  IF NEW.kind IS DISTINCT FROM OLD.kind THEN", "  IF false THEN",
     [f"{T_CP7}::test_h2_principal_kind_cannot_change"]),
    ("A5", "review of pre-0016 bindings revokes nothing", M17,
     "WHERE rb.revoked_at IS NULL AND p.kind IS DISTINCT FROM r.principal_kind", "WHERE false",
     [f"{T_CP7}::test_h1_bindings_that_predate_the_kind_rule_are_revoked_on_review"]),
    # ---------------------------------------------------------------- authentication
    ("U1", "azp ignored with a single audience", "backend/axiom/auth/oidc.py",
     'if (len(aud) > 1 or "azp" in claims) and', "if len(aud) > 1 and",
     [f"{T_OIDCU}::test_rejected_claims"]),
    ("U2", "login keeps the previous session", "backend/axiom/api/app.py",
     'sessions.revoke(previous, reason="replaced_by_login")', "None",
     [f"{T_SSO}::test_login_rotates_the_session_and_keeps_codes_out_of_the_url_trail"]),
    ("U3", "access-log redaction not installed on the server", "backend/axiom/server.py",
     "        access.addFilter(RedactSignInQuery())", "        pass",
     [f"{T_OIDCU}::test_the_deployed_server_installs_the_redaction_and_ignores_forwarding_headers"]),
    ("U4", "secret files outside the allowed directories accepted", "backend/axiom/secretrefs.py",
     "if not any(real == d or d in real.parents for d in self.file_dirs):", "if False:",
     [T_SREF]),
    ("U5", "production accepts environment secret references", "backend/axiom/config.py",
     'if not (self.oidc_client_secret_ref or "").startswith("secretref:file/"):', "if False:",
     [f"{T_SSO}::test_production_sso_settings_are_checked"]),
    ("U6", "no JWKS refresh on an unknown key", "backend/axiom/auth/oidc.py",
     "tok = jwt.decode(id_token, self._keys(refresh=True), algorithms=ALGORITHMS)", "raise",
     [f"{T_OIDCU}::test_unknown_key_id_refreshes_the_key_set_once",
      f"{T_SSO}::test_signing_key_rotation_at_the_local_idp_is_followed"]),
    # ---------------------------------------------------------------- verification worker
    ("W1", "no permission check before calling the endpoint", W,
     '                authz.require("verification.record", case["scope_id"])\n'
     '                authz.require("evidence.upload", case["scope_id"])\n', "",
     [f"{T_VW}::test_authority_is_evaluated_when_the_job_runs_not_when_it_was_queued",
      f"{T_VW}::test_project_boundary_binding_elsewhere_gives_no_authority"]),
    ("W2", "lease not re-checked at commit", W,
     "                jc.fenced(conn)\n                svc = CaseService", "                svc = CaseService",
     [f"{T_VW}::test_a_worker_that_lost_its_lease_while_checking_records_nothing"]),
    ("W3", "commit uses the current case version instead of the one read", W,
     "svc.record_verification(case_id, version,",
     'svc.record_verification(case_id, conn.execute("SELECT record_version FROM axiom.finding_cases WHERE id = %s", '
     '(case_id,)).fetchone()["record_version"],',
     [f"{T_VW}::test_a_case_changed_during_the_check_is_not_silently_overwritten"]),
    ("W4", "already-recorded check not recognised (first idempotency layer)", W,
     "                if prior:\n", "                if False:\n",
     [f"{T_VW}::test_a_crash_after_commit_does_not_record_twice"]),
    ("W5", "unavailable endpoint not retried", W,
     "                if attempt < jc.job[\"max_attempts\"]:", "                if False:",
     [f"{T_VW}::test_an_unavailable_endpoint_is_retried_then_recorded_inconclusive",
      f"{T_VW}::test_a_stopped_endpoint_is_unavailable_not_passed"]),
    ("W6", "stale observations accepted", C,
     "    if exchange.received_at - observed_at > max_age:", "    if False:",
     [f"{T_VCU}::test_rules", f"{T_VW}::test_missing_stale_contradictory_or_refused_evidence_is_inconclusive"]),
    ("W7", "contradictory results not detected", C,
     "    if any(len(v) > 1 for v in requested.values()):", "    if False:",
     [f"{T_VCU}::test_rules", f"{T_VW}::test_missing_stale_contradictory_or_refused_evidence_is_inconclusive"]),
    ("W8", "different deployment not detected", C,
     "    if digest != target_digest:", "    if False:",
     [f"{T_VCU}::test_rules", f"{T_VW}::test_missing_stale_contradictory_or_refused_evidence_is_inconclusive"]),
    ("W9", "observation guard accepts another recorder", M18,
     "  IF NEW.recorded_by IS DISTINCT FROM axiom.current_principal() THEN", "  IF false THEN",
     [f"{T_VW}::test_observations_cannot_be_forged_or_changed"]),
    ("W10", "verification role also gets case.reopen", M18,
     "('verification_worker', 'evidence.read:confidential');",
     "('verification_worker', 'evidence.read:confidential'), ('verification_worker', 'case.reopen');",
     [f"{T_VW}::test_the_verification_identity_holds_only_its_workload_permissions",
      f"{T_VW}::test_the_verification_identity_cannot_reopen_close_or_decide"]),
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
        failed = [l for l in out.splitlines() if l.startswith("FAILED ")]
        verdict = "CAUGHT" if rc != 0 else "SURVIVED"
        print(f"{mid} {name}: {verdict} ({tail})", flush=True)
        for f in failed:                          # the summary line carries the first assertion: the reason
            print(f"     {f[:260]}", flush=True)
    all_targets = sorted({t for m in M for t in m[5] if not only or m[0] in only})
    rc, tail, _ = run(all_targets)
    print(f"sanity: all targeted tests on the restored tree: rc={rc} ({tail})")


if __name__ == "__main__":
    main()
