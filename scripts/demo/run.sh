#!/usr/bin/env bash
# Reproduce the remediation demonstration (docs/DEMO.md). Local only: Docker, the test PostgreSQL, a local registry,
# a local Keycloak and Chromium. No model is called; the tracker is an in-process fake.
#
#   scripts/demo/run.sh [OUTPUT_DIR]
#
# Behind a TLS-intercepting proxy, set BUILD_CA=/path/to/ca.pem (image builds and the one Trivy database download).
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="$(realpath -m "${1:-demo-out}")"
mkdir -p "$OUT"
PY=${PYTHON:-.venv/bin/python}

[ -f frontend/dist/index.html ] || (cd frontend && npm ci --no-audit --no-fund && npm run build)
scripts/dev/test-db.sh start >/dev/null
python3 scripts/demo/lab.py up | tee "$OUT/lab.json"

export AXIOM_DEMO=1 AXIOM_DEMO_OUT="$OUT" AXIOM_REQUIRE_UI=1
AXIOM_DEMO_COMMIT="$(git rev-parse HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then AXIOM_DEMO_COMMIT="$AXIOM_DEMO_COMMIT+uncommitted"; fi
export AXIOM_DEMO_COMMIT
"$PY" -m pytest -p no:cacheprovider -q -rA tests/integration/test_demo_remediation.py 2>&1 | tee "$OUT/pytest.log"
echo "results: $OUT/results.json"
