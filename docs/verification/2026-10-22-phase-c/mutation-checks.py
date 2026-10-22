import subprocess, pathlib
T_ADV="tests/integration/test_investigation_adversarial.py"; T_INV="tests/integration/test_investigation.py"
muts = [
 ("backend/axiom/investigation/claims.py", "    if missing:\n        return Result(", "    if False:\n        return Result(", T_ADV+"::test_fabricated_citations_are_rejected"),
 ("backend/axiom/investigation/claims.py", "            if subj.vulnerability_ref and a.get(\"vulnerability_ref\") != subj.vulnerability_ref:", "            if False:", T_ADV+"::test_valid_but_irrelevant_citations_are_rejected"),
 ("backend/axiom/investigation/claims.py", "                if says_present != claims_present:", "                if False:", "tests/integration/test_evaluation_harness.py::test_case[H2]"),
 ("backend/axiom/investigation/claims.py", "            if not other_side or not (set(c.get(\"member_keys\", [])) & cited):", "            if False:", T_ADV+"::test_ignoring_a_recorded_contradiction_downgrades_the_claim"),
 ("backend/axiom/investigation/snapshots.py", "    pm[\"ref_digest\"] = None\n    pm[\"content_withheld\"]", "    pm[\"content_withheld\"]", T_ADV+"::test_content_above_the_route_classification_never_reaches_the_model"),
 ("backend/axiom/investigation/runner.py", "        if not authz.has(\"investigation.run\", case[\"scope_id\"], principal_id=run[\"requested_by\"]):", "        if False:", T_INV+"::test_cancellation_and_revocation_end_the_run"),
 ("backend/axiom/investigation/runner.py", "        if route[\"status\"] != \"approved\":", "        if False:", T_INV+"::test_disabled_route_fails_without_fallback"),
 ("backend/axiom/domains/cases/service.py", "            if unreviewed:", "            if False:", T_INV+"::test_assessment_cites_the_run_only_after_human_review"),
 ("backend/axiom/migrations/0013_investigation.sql", "  IF axiom_auth.principal_kind(actor) IS DISTINCT FROM 'human' AND NOT allowed THEN", "  IF false THEN", T_INV+"::test_workload_principals_cannot_record_consequential_decisions_or_reviews"),
 ("backend/axiom/investigation/tools.py", "    if name not in {g[\"tool\"] for g in tc.run[\"tool_grants\"]}:", "    if False:", T_ADV+"::test_tool_argument_abuse_and_cross_tenant_arguments_are_refused"),
 ("backend/axiom/investigation/gateway.py", "        system_r, n1 = redact(system)\n        user_r, n2 = redact(user)", "        system_r, n1 = system, 0\n        user_r, n2 = user, 0", T_ADV+"::test_prompt_injection_in_scanner_text_changes_nothing"),
 ("backend/axiom/domains/cases/sla.py", "        if e[\"event_type\"] != \"case.deferred\" or reason not in authorised:", "        if e[\"event_type\"] != \"case.deferred\":", "tests/integration/test_sla_timers.py::test_deferral_without_an_authorised_reason_keeps_the_clock_running"),
 ("backend/axiom/domains/reports/service.py", "            meta_ok = readable or self.authz.has(meta_perm, case[\"scope_id\"])", "            meta_ok = True", "tests/integration/test_report_depth.py::test_evidence_package_withholds_content_the_requester_cannot_read"),
 ("backend/axiom/investigation/runner.py", "            if malformed <= 1:", "            if malformed <= 5:", T_ADV+"::test_malformed_output_gets_one_corrective_retry"),
]
for f, old, new, test in muts:
    p = pathlib.Path(f); s = p.read_text()
    assert s.count(old) == 1, (f, old)
    p.write_text(s.replace(old, new))
    try:
        r = subprocess.run(["uv","run","pytest","-q","-x","-p","no:cacheprovider",test], capture_output=True, text=True, timeout=900)
        last = [l for l in r.stdout.splitlines() if " passed" in l or " failed" in l or "error" in l][-1:]
        print("KILLED" if r.returncode else "SURVIVED", f.split('/')[-1], "|", new.strip()[:60].replace("\n"," "), last)
    finally:
        p.write_text(s)
