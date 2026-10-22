#!/usr/bin/env bash
# Reproducibility manifest for the exact committed tree under test.
#
#   scripts/ci/input-manifest.sh [OUT_FILE]
#
# Fails unless the working tree equals HEAD (no modified, staged or untracked non-ignored files), so a test run can be
# tied to one commit. It then records:
#   * the commit and its git tree hash (covers every tracked file);
#   * an "executable inputs" digest over the tracked blobs that decide behaviour: application code, migrations,
#     provisioning SQL, scripts, workflow files, dependency locks, Dockerfile, Compose configuration and tests;
#   * ignored files present under those paths (anything other than caches fails the check, because an ignored file
#     there could change behaviour without changing the digest);
#   * external inputs that are pinned (lock file, image digests, action commits) and those that are NOT pinned by the
#     tree (host PostgreSQL binaries, Docker, uv and Python on the runner).
# Mutable development data (.var/, database clusters, uploaded evidence, object stores) is excluded from any claim.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OUT_FILE="${1:-/dev/stdout}"
INPUTS=(backend db scripts .github deployments tests pyproject.toml uv.lock Dockerfile .dockerignore)

dirty=$(git status --porcelain --untracked-files=normal)
if [ -n "$dirty" ]; then
  echo "working tree differs from HEAD; refusing to describe it as a committed tree:" >&2
  echo "$dirty" >&2
  exit 1
fi
for p in backend/axiom/migrations db scripts .github/workflows deployments uv.lock pyproject.toml Dockerfile tests; do
  [ -n "$(git ls-files -- "$p" | head -1)" ] || { echo "no tracked files under $p" >&2; exit 1; }
done
ignored=$(git ls-files --others --ignored --exclude-standard -- "${INPUTS[@]}" \
          | grep -vE '(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache)/|\.pyc$' || true)
if [ -n "$ignored" ]; then
  echo "ignored files inside executable-input paths (would not be covered by the digest):" >&2
  echo "$ignored" >&2
  exit 1
fi
inputs_digest=$(git ls-tree -r HEAD -- "${INPUTS[@]}" | sha256sum | cut -d' ' -f1)
{
  echo "commit:            $(git rev-parse HEAD)"
  echo "tree:              $(git rev-parse 'HEAD^{tree}')"
  echo "executable inputs: sha256:$inputs_digest over 'git ls-tree -r HEAD -- ${INPUTS[*]}'"
  echo "tracked files:     $(git ls-files | wc -l) total, $(git ls-files -- "${INPUTS[@]}" | wc -l) in executable-input paths"
  echo "migrations:        $(git ls-files -- backend/axiom/migrations | grep -c '\.sql$') files"
  echo "pinned by the tree:"
  echo "  uv.lock sha256:  $(sha256sum uv.lock | cut -d' ' -f1)"
  grep -hoE '[a-z0-9./-]+:[0-9][^@" ]*@sha256:[0-9a-f]{64}' Dockerfile deployments/compose/compose.yaml scripts/verify/*.sh \
    | sort -u | sed 's/^/  image:          /'
  grep -hoE 'uses: [^ ]+@[0-9a-f]{40}' .github/workflows/*.yml | sort -u | sed 's/^/  action:         /'
  echo "NOT pinned by the tree (runner environment, recorded here for this run):"
  echo "  python:          $(python3 --version 2>&1)"
  echo "  uv:              $(uv --version 2>&1)"
  echo "  postgres:        $("${PG_BIN:-/usr/lib/postgresql/16/bin}/postgres" --version 2>&1)"
  echo "  docker:          $(docker --version 2>&1)"
  echo "  pip-installed uv inside the image build: uv==0.11.32 (version pinned, hash not pinned)"
  echo "excluded from reproducibility claims: .var/ (logs, clusters), uploaded evidence, object-store contents, .env files"
} > "$OUT_FILE"
