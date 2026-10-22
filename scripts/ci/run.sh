#!/usr/bin/env bash
# The CI pipeline. The hosted workflow (.github/workflows/ci.yml) only provisions tools and runs this script, so
# what CI checks is exactly what a developer can run locally:
#
#   scripts/ci/run.sh                 # needs PostgreSQL 16 server binaries, Docker, uv
#
# Stages: locked dependency sync; byte-compilation; tracked-file secret scan; foundation verification on a fresh
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

stage "dependencies (locked)"
uv sync --frozen 2>&1 | grep -v UV_NATIVE | tail -3; record dependencies "${PIPESTATUS[0]}"

stage "byte-compile"
uv run --frozen python -m compileall -q backend tests >/dev/null 2>&1; record compile $?

stage "secret scan (tracked files)"
hits=$(git ls-files -z | xargs -0 grep -lE "BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|AKIA[0-9A-Z]{16}" 2>/dev/null || true)
if [ -n "$hits" ]; then echo "$hits"; record secret-scan 1; else record secret-scan 0; fi
tracked_env=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$' || true)
if [ -n "$tracked_env" ]; then echo "$tracked_env"; record no-env-files 1; else record no-env-files 0; fi

stage "foundation verification (fresh cluster + SeaweedFS + full suite)"
OUT="$OUT/foundation" scripts/verify/foundation.sh > "$OUT/foundation.stdout" 2>&1
grep -E "^[0-9]+ passed|passed,|failed|error" "$OUT/foundation/verify.log" | tail -3
grep -q "pytest exit=0" "$OUT/foundation/verify.log"; record foundation $?

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
