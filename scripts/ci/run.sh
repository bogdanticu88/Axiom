#!/usr/bin/env bash
# The CI pipeline. The hosted workflow (.github/workflows/ci.yml) only provisions tools and runs this script, so
# what CI checks is exactly what a developer can run locally:
#
#   scripts/ci/run.sh                 # needs PostgreSQL 16 server binaries, Docker, uv
#
# Stages: input manifest of the exact committed tree (refuses a dirty tree unless CI_ALLOW_DIRTY=1); locked
# dependency sync; byte-compilation; tracked-file secret scan; foundation verification on a fresh
# separate cluster with S3 (full pytest suite, including the real-SIGKILL, restore and concurrency tests);
# physical snapshot restore drill on its own cluster; Compose fresh-install smoke with a rebuilt image.
# Exit status is non-zero if any stage fails. Logs go to .var/ci/<stamp>/.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${CI_OUT:-$ROOT/.var/ci/$STAMP}"
mkdir -p "$OUT"
FAILED=()
stage() { echo; echo "##### $1 ($(date -u +%H:%M:%SZ))"; }
record() { if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1 (exit $2)"; FAILED+=("$1"); fi; }

stage "input manifest (exact committed tree)"
if [ "${CI_ALLOW_DIRTY:-0}" = "1" ]; then
  echo "CI_ALLOW_DIRTY=1: working tree may differ from HEAD; results do not describe a committed tree"
  git status --porcelain | head -20; record input-manifest 0
else
  scripts/ci/input-manifest.sh "$OUT/input-manifest.txt"; rc=$?; cat "$OUT/input-manifest.txt" 2>/dev/null
  record input-manifest $rc
fi

stage "dependencies (locked)"
uv sync --frozen 2>&1 | grep -v UV_NATIVE | tail -3; record dependencies "${PIPESTATUS[0]}"

stage "byte-compile"
uv run --frozen python -m compileall -q backend tests >/dev/null 2>&1; record compile $?

stage "secret scan (tracked files)"
hits=$(git ls-files -z | xargs -0 grep -lE "BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|AKIA[0-9A-Z]{16}" 2>/dev/null || true)
if [ -n "$hits" ]; then echo "$hits"; record secret-scan 1; else record secret-scan 0; fi
tracked_env=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$' || true)
if [ -n "$tracked_env" ]; then echo "$tracked_env"; record no-env-files 1; else record no-env-files 0; fi

stage "requirements register (every row has a recognised status)"
python3 scripts/dev/register-counts.py | tail -4; record register "${PIPESTATUS[0]}"

stage "GitHub Actions pins (full commit hashes, verified against the official repositories)"
scripts/ci/check-action-pins.sh; record action-pins $?

stage "foundation verification (fresh cluster + SeaweedFS + full suite, incl. evaluation harness)"
rm -rf "$OUT/eval"
AXIOM_EVAL_OUT="$OUT/eval" OUT="$OUT/foundation" scripts/verify/foundation.sh > "$OUT/foundation.stdout" 2>&1
grep -E "^[0-9]+ passed|passed,|failed|error" "$OUT/foundation/verify.log" | tail -3
grep -q "pytest exit=0" "$OUT/foundation/verify.log"; record foundation $?

stage "evaluation report (from this run's harness results)"
python3 evaluation/report.py "$OUT/eval/results.jsonl" "$OUT/eval/report.md" > /dev/null; rc=$?
grep -E "^\| (Presence|Unsupported|Missed)" "$OUT/eval/report.md" | head -6; record evaluation-report $rc

stage "restore drill: physical snapshot rollback"
AXIOM_RUN_DRILLS=1 uv run --frozen pytest -q tests/drills -p no:cacheprovider 2>&1 | grep -v UV_NATIVE \
  | tee "$OUT/restore-drill.log" | tail -2
record restore-drill "${PIPESTATUS[0]}"

stage "compose fresh-install smoke (image rebuilt)"
BUILD=1 scripts/verify/compose-smoke.sh > "$OUT/compose-smoke.log" 2>&1; rc=$?
grep -E "^ok |SMOKE" "$OUT/compose-smoke.log" | grep -v LockRing; record compose-smoke $rc

echo
if [ ${#FAILED[@]} -eq 0 ]; then echo "CI PASS ($OUT)"; exit 0; fi
echo "CI FAIL: ${FAILED[*]} ($OUT)"; exit 1
