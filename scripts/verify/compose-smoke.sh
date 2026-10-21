#!/usr/bin/env bash
# Fresh-install smoke test of the Compose profile under a throwaway project name with new
# volumes and generated secrets. Removes everything afterwards (docker compose down -v).
#
#   scripts/verify/compose-smoke.sh            # uses existing image axiom-backend:dev
#   BUILD=1 scripts/verify/compose-smoke.sh    # rebuild the image first
#
# Behind a TLS-intercepting proxy set BUILD_CA=/path/to/ca.pem for the build secret.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CDIR="$ROOT/deployments/compose"
P="axiom-smoke-$(date -u +%H%M%S)"
ENVF="$(mktemp)"; trap 'docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" down -v >/dev/null 2>&1; rm -f "$ENVF"' EXIT
PORT=${PORT:-18010}
gen() { python3 -c 'import secrets;print(secrets.token_hex(16))'; }
cat > "$ENVF" <<E
AXIOM_PG_SUPERUSER_PASSWORD=$(gen)
AXIOM_MIGRATOR_PASSWORD=$(gen)
AXIOM_APP_PASSWORD=$(gen)
AXIOM_RELAY_PASSWORD=$(gen)
AXIOM_ADMIN_CLI_PASSWORD=$(gen)
AXIOM_S3_ACCESS_KEY=$(gen)
AXIOM_S3_SECRET_KEY=$(gen)
AXIOM_API_PORT=$PORT
E
if [ "${BUILD:-0}" = "1" ]; then
  args=(--network host -t axiom-backend:dev)
  [ -n "${BUILD_CA:-}" ] && args+=(--secret "id=ca,src=$BUILD_CA")
  [ -n "${HTTPS_PROXY:-}" ] && args+=(--build-arg "HTTPS_PROXY=$HTTPS_PROXY")
  docker build "${args[@]}" "$ROOT" >/dev/null 2>&1 || { echo "image build failed"; exit 1; }
  echo "image built: $(docker image inspect axiom-backend:dev --format '{{.Id}}')"
fi
dc() { docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" "$@"; }
fail() { echo "SMOKE FAIL: $*"; dc logs --no-color | tail -40; exit 1; }
echo "project $P"
dc up -d --no-build >/dev/null 2>&1 || fail "compose up"
for i in $(seq 1 60); do
  [ "$(dc ps api --format '{{.Health}}')" = "healthy" ] && break; sleep 2
done
[ "$(dc ps api --format '{{.Health}}')" = "healthy" ] || fail "api not healthy"
dc logs app-init --no-color | grep -q "applied: 0001, 0002, 0003" || fail "migrations not applied on fresh install"
echo "ok   fresh install: migrations applied, api healthy"
B="http://127.0.0.1:$PORT/api/v1"
tok() { dc exec -T api python -m axiom.devtools mint --dir /var/lib/axiom/dev-idp --sub "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
A=$(tok alice); C=$(tok consult)
[ "$(code "$B/cases")" = 401 ] || fail "unauthenticated request not 401"; echo "ok   no token -> 401"
H=(-H "Authorization: Bearer $A" -H "X-Axiom-Tenant: demo")
PAY=$(dc exec -T postgres psql -U postgres -d axiom -tAc "SELECT id FROM axiom.scopes WHERE name='payments' AND tenant_id=(SELECT id FROM axiom.tenants WHERE slug='demo')")
DATA='{"scanner":"trivy","finding":"CVE-2099-0001","synthetic":true}'
SHA=$(printf '%s' "$DATA" | sha256sum | cut -d' ' -f1)
EV=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d "{\"scope_id\":\"$PAY\",\"sha256\":\"$SHA\",\"size\":${#DATA},\"media_type\":\"application/json\",\"classification\":\"internal\"}" "$B/evidence" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])') || fail "initiate evidence"
[ "$(code "${H[@]}" -X PUT --data-binary "$DATA" "$B/evidence/$EV/content")" = 200 ] || fail "upload"
ST=$(curl -sf "${H[@]}" -X POST "$B/evidence/$EV/finalise" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')
[ "$ST" = verified ] || fail "finalise status $ST"
[ "$(curl -sf "${H[@]}" "$B/evidence/$EV/content?purpose=smoke")" = "$DATA" ] || fail "download content mismatch"
echo "ok   evidence upload -> verified -> download via S3 (SeaweedFS)"
dc exec -T objects sh -c "ls -R /data" >/dev/null 2>&1 || true
BAD=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d "{\"scope_id\":\"$PAY\",\"sha256\":\"$(printf '0%.0s' $(seq 64))\",\"size\":4,\"media_type\":\"text/plain\",\"classification\":\"internal\"}" "$B/evidence" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -sf "${H[@]}" -X PUT --data-binary "abcd" "$B/evidence/$BAD/content" >/dev/null
ST=$(curl -sf "${H[@]}" -X POST "$B/evidence/$BAD/finalise" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["status"],d["rejection_reason"])')
[ "$ST" = "rejected digest_mismatch" ] || fail "mismatch not rejected: $ST"; echo "ok   digest mismatch -> rejected"
CASE=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d "{\"scope_id\":\"$PAY\",\"title\":\"smoke case\"}" "$B/cases" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
R=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d '{"expected_version":0,"rationale":"triage"}' "$B/cases/$CASE/commands/start-investigation" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["workflow"],d["record_version"])')
[ "$R" = "investigating 1" ] || fail "transition result $R"
[ "$(code "${H[@]}" -H 'Content-Type: application/json' -d '{"expected_version":0,"rationale":"again"}' "$B/cases/$CASE/commands/start-investigation")" = 409 ] || fail "stale not 409"
echo "ok   case create, start-investigation, stale version -> 409"
[ "$(code -H "Authorization: Bearer $C" -H "X-Axiom-Tenant: demo-two" "$B/cases/$CASE")" = 404 ] || fail "cross-tenant read not 404"
[ "$(code -H "Authorization: Bearer $A" -H "X-Axiom-Tenant: demo-two" "$B/cases")" = 403 ] || fail "non-member tenant not 403"
echo "ok   consultant in other tenant -> 404; non-member tenant selection -> 403"
N=$(dc exec -T postgres psql -U postgres -d axiom -tAc "SELECT count(*) FROM axiom.audit_events a JOIN axiom.case_events e ON e.audit_event_id=a.id AND e.tenant_id=a.tenant_id WHERE e.case_id='$CASE'")
[ "$N" = 2 ] || fail "expected 2 audited case events, got $N"; echo "ok   case events linked to audit rows: $N"
FIX="$ROOT/tests/fixtures/trivy/debian-bullseye-20230612-slim.subset.json"
FSHA=$(sha256sum "$FIX" | cut -d' ' -f1); FSIZE=$(stat -c %s "$FIX")
FEV=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d "{\"scope_id\":\"$PAY\",\"sha256\":\"$FSHA\",\"size\":$FSIZE,\"media_type\":\"application/json\",\"classification\":\"internal\"}" "$B/evidence" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -sf "${H[@]}" -X PUT --data-binary @"$FIX" "$B/evidence/$FEV/content" >/dev/null
curl -sf "${H[@]}" -X POST "$B/evidence/$FEV/finalise" >/dev/null
RUN=$(curl -sf "${H[@]}" -H 'Content-Type: application/json' -d "{\"evidence_id\":\"$FEV\",\"adapter\":\"trivy_json\",\"scope_id\":\"$PAY\"}" "$B/imports" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])') || fail "import request"
ST=""
for i in $(seq 1 40); do
  ST=$(curl -sf "${H[@]}" "$B/ingestion-runs/$RUN" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["status"],d["coverage"],d["counts"].get("findings"))')
  case "$ST" in completed*|failed*) break;; esac; sleep 2
done
[ "$ST" = "completed complete 30" ] || fail "import via worker: $ST"
NC=$(curl -sf "${H[@]}" "$B/cases?limit=200" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
echo "ok   Trivy import via API + ingest-worker: $ST; cases visible: $NC"
dc up -d --no-build --force-recreate db-init app-init >/dev/null 2>&1
for i in $(seq 1 60); do   # wait for the recreated one-shot container to finish (no fixed sleep)
  [ "$(dc ps -a app-init --format '{{.State}}')" = "exited" ] && break; sleep 2
done
[ "$(dc ps -a app-init --format '{{.State}} {{.ExitCode}}')" = "exited 0" ] || fail "re-init did not exit cleanly"
dc logs app-init --no-color | grep -q "already seeded" || fail "re-init not idempotent"
dc logs app-init --no-color | grep -q "applied: none" || fail "re-migration applied something"
echo "ok   re-running init: migrations 'applied: none', seed 'already seeded'"
echo "SMOKE PASS ($P)"
