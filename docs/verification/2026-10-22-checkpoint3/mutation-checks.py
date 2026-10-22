import subprocess, sys, pathlib
muts = [
 ("backend/axiom/domains/reports/service.py", "AND NOT (s.status = 'revised' AND s.ended_at <= %(t)s)),", "AND s.status <> 'revised'),", "tests/integration/test_report_depth.py"),
 ("backend/axiom/jobs/witness.py", "return mine[:-keep] if keep >= 1 else []", "return mine", "tests/unit/test_witness_pruning.py"),
 ("backend/axiom/jobs/witness.py", "if _owner(n) == worker", "if n.endswith('-' + worker)", "tests/unit/test_witness_pruning.py"),
 ("backend/axiom/domains/cases/sla.py", "r = _insert(conn, ctx, case[\"id\"], \"remediation\", cycle, case[\"priority\"], policy_id, snapshot, start,", "r = _insert(conn, ctx, case[\"id\"], \"remediation\", cycle, case[\"priority\"], policy_id, snapshot, now,", "tests/integration/test_sla_timers.py"),
 ("backend/axiom/domains/cases/sla.py", "if reason == \"accepted_risk\":\n        return \"risk_accepted\"", "if reason == \"accepted_risk\":\n        return \"met\"", "tests/integration/test_sla_timers.py"),
]
for f, old, new, test in muts:
    p = pathlib.Path(f); s = p.read_text()
    assert s.count(old) == 1, (f, old)
    p.write_text(s.replace(old, new))
    try:
        r = subprocess.run(["uv","run","pytest","-q","-x","-p","no:cacheprovider",test], capture_output=True, text=True, timeout=900)
        last = [l for l in r.stdout.splitlines() if "passed" in l or "failed" in l][-1:]
        print("KILLED" if r.returncode else "SURVIVED", f, new[:50], last)
    finally:
        p.write_text(s)
