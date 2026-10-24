#!/usr/bin/env bash
# Fresh-install smoke test of the Compose profile under a throwaway project name with new
# volumes and generated secrets. Removes everything afterwards (docker compose down -v).
#
#   scripts/verify/compose-smoke.sh            # uses existing image axiom-backend:dev
#   BUILD=1 scripts/verify/compose-smoke.sh    # rebuild the image first
#
# Behind a TLS-intercepting proxy set BUILD_CA=/path/to/ca.pem for the build secret.
#
# On failure the script prints what it can about the failure (see diagnose below), then removes the project. Time
# limits for that part, each including the grace period between SIGTERM and SIGKILL for commands that overrun:
#   diagnostics  DIAG_LIMIT seconds in total (default 120)
#   cleanup      CLEANUP_LIMIT + CLEANUP_GRACE seconds (default 60 + 10) for 'docker compose down -v'
# so collection and cleanup after a failure take at most 190 seconds by default, whatever state Docker is in (plus
# the moment the output filter needs to finish). The exit status is always that of
# the original failure; a cleanup that does not finish is reported, not turned into another status.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CDIR="$ROOT/deployments/compose"
P="axiom-smoke-$(date -u +%H%M%S)"
DIAG_LIMIT=${DIAG_LIMIT:-120}
KILL_GRACE=5
CLEANUP_LIMIT=${CLEANUP_LIMIT:-60}
CLEANUP_GRACE=10
ENVF="$(mktemp)"; buildlog=""; UPLOG=""
cleanup() {
  if ! timeout -k "$CLEANUP_GRACE" "$CLEANUP_LIMIT" \
      docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" down -v >/dev/null 2>&1; then
    echo "cleanup: 'docker compose down -v' failed or did not finish within ${CLEANUP_LIMIT} s; project $P may remain"
  fi
  rm -f "$ENVF" "$buildlog" "$UPLOG"
}
trap cleanup EXIT
PORT=${PORT:-18010}
IDP_PORT=${IDP_PORT:-18011}
gen() { python3 -c 'import secrets;print(secrets.token_hex(16))'; }
DEMO_PASSWORD=$(gen)
cat > "$ENVF" <<E
AXIOM_PG_SUPERUSER_PASSWORD=$(gen)
AXIOM_MIGRATOR_PASSWORD=$(gen)
AXIOM_APP_PASSWORD=$(gen)
AXIOM_RELAY_PASSWORD=$(gen)
AXIOM_ADMIN_CLI_PASSWORD=$(gen)
AXIOM_S3_ACCESS_KEY=$(gen)
AXIOM_S3_SECRET_KEY=$(gen)
AXIOM_API_PORT=$PORT
AXIOM_IDP_PORT=$IDP_PORT
AXIOM_OIDC_CLIENT_SECRET=$(gen)
AXIOM_DEMO_PASSWORD=$DEMO_PASSWORD
E
# Everything printed about a failure passes through redact() (scripts/verify/smoke_redact.py): the secrets this script
# generated (all values in $ENVF), token shapes, Authorization header values, user information in URLs and private key
# blocks are replaced. It is a filter for known shapes, not a guarantee; see that file. The rendered Compose
# configuration and container environments are never printed, because they contain those secrets.
redact() {
  python3 "$ROOT/scripts/verify/smoke_redact.py" "$ENVF" 2>/dev/null || echo "(redaction failed; output withheld)"
}
# --- images. Every image the test needs is pulled once, one at a time, by the digest it is pinned to, before the build
# and before 'docker compose up': the Dockerfile's base images (with BUILD=1) and the Compose services' images, read
# from those files so that the digests have one source. Compose names the PostgreSQL image for two services and would
# otherwise request it twice at once. An image already present under its pinned reference is not pulled again; on a
# fresh runner nothing is present, so the install stays cold. The build and 'up' then find every pinned image locally
# (the build still resolves the Dockerfile syntax image by its tag). A failed pull ends the test with its output.
images=()
if [ "${BUILD:-0}" = "1" ]; then
  while IFS= read -r ref; do images+=("$ref"); done < <(sed -n 's/^ARG [A-Z_]*_IMAGE=//p' "$ROOT/Dockerfile")
fi
cimages=$(docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" config --images 2>&1) \
  || { echo "SMOKE FAIL: could not list the Compose images:"; echo "$cimages" | redact | tail -20; exit 1; }
while IFS= read -r ref; do
  [ "$ref" = axiom-backend:dev ] || images+=("$ref")      # built by this script, never pulled
done <<<"$cimages"
pulllog=$(mktemp)
for ref in $(printf '%s\n' "${images[@]}" | awk '!seen[$0]++'); do
  case "$ref" in
    *@sha256:*) ;;
    *) echo "SMOKE FAIL: image not pinned by digest: $ref"; rm -f "$pulllog"; exit 1 ;;
  esac
  if docker image inspect "$ref" >/dev/null 2>&1; then
    echo "image present: $ref"
    continue
  fi
  t0=$SECONDS
  if ! docker pull "$ref" >"$pulllog" 2>&1; then
    echo "image pull failed: $ref; its output:"; tail -20 "$pulllog" | redact; rm -f "$pulllog"
    echo "SMOKE FAIL: image pull"; exit 1
  fi
  echo "image pulled in $((SECONDS - t0)) s: $ref"
done
rm -f "$pulllog"
if [ "${BUILD:-0}" = "1" ]; then
  args=(--network host -t axiom-backend:dev)
  [ -n "${BUILD_CA:-}" ] && args+=(--secret "id=ca,src=$BUILD_CA")
  [ -n "${HTTPS_PROXY:-}" ] && args+=(--build-arg "HTTPS_PROXY=$HTTPS_PROXY")
  buildlog=$(mktemp)
  if ! docker build "${args[@]}" "$ROOT" >"$buildlog" 2>&1; then
    echo "image build failed; last lines of the build output:"; tail -40 "$buildlog" | redact; exit 1
  fi
  rm -f "$buildlog"
  echo "image built: $(docker image inspect axiom-backend:dev --format '{{.Id}}')"
fi
dc() { docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" "$@"; }

# --- failure diagnostics. Best effort: output is truncated and redacted, and nothing here can change the exit status
# of the failure being reported. Time: every command runs under bounded(), which limits it to its own allowance or to
# what is left of DIAG_LIMIT, whichever is less, and kills it KILL_GRACE seconds after SIGTERM if it is still running.
# 'timeout' signals the command's whole process group, so helpers the Docker CLI starts are stopped with it.
diagnose() {
  (
    set +e
    end=$((SECONDS + DIAG_LIMIT))
    # one second of slack for the whole-second resolution of SECONDS
    rest() { echo $(( end - SECONDS - KILL_GRACE - 1 )); }
    bounded() {
      local want=$1 r; shift
      r=$(rest); [ "$r" -ge 1 ] || return 124
      [ "$want" -lt "$r" ] && r=$want
      timeout -k "$KILL_GRACE" "$r" "$@"
    }
    said=""
    left() { [ "$(rest)" -ge 1 ] && return 0; [ -n "$said" ] || echo "(diagnostics time limit reached)"; said=1; return 1; }
    echo "--- diagnostics for project $P (bounded, redacted)"
    echo "--- containers"
    bounded 20 docker ps -a --filter "label=com.docker.compose.project=$P" \
      --format 'table {{.Label "com.docker.compose.service"}}\t{{.State}}\t{{.Status}}\t{{.Image}}' 2>&1 | head -30
    echo "--- container state and the last health-check results"
    left && for c in $(bounded 20 docker ps -aq --filter "label=com.docker.compose.project=$P" 2>/dev/null | head -20); do
      left || break
      bounded 10 docker inspect --format \
        '{{index .Config.Labels "com.docker.compose.service"}}: state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} error={{printf "%.200s" .State.Error}}' \
        "$c" 2>&1 | cut -c1-300
      left || break
      bounded 10 docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}  check exit {{.ExitCode}}: {{printf "%.200s" .Output}}{{"\n"}}{{end}}{{end}}' \
        "$c" 2>/dev/null | grep -v '^$' | tail -3
    done
    echo "--- service logs (last lines each)"
    left && for svc in postgres db-init app-init idp-init keycloak api job-worker objects; do
      left || break
      n=40; [ "$svc" = objects ] && n=10
      echo "## $svc"
      bounded 20 docker compose -p "$P" -f "$CDIR/compose.yaml" --env-file "$ENVF" logs --no-color --tail "$n" "$svc" 2>&1 \
        | cut -c1-400 | tail -"$n"
    done
    left || true                                  # says so once if the limit cut collection short
  ) 2>&1 | redact | stdbuf -oL head -400              # line-buffered, so lines appear as they are collected
  return 0
}
fail() {
  echo "SMOKE FAIL: $(printf '%s' "$*" | redact)"
  diagnose || true
  exit 1
}
# An unexpected failing command (set -e) would otherwise end the script with no message at all.
on_error() {
  local rc=$? line=$1
  trap - ERR
  echo "SMOKE FAIL: unexpected exit $rc at line $line: $(sed -n "${line}p" "$0" | cut -c1-160 | redact)"
  diagnose || true
  exit "$rc"
}
trap 'on_error $LINENO' ERR
echo "project $P"
UPLOG=$(mktemp)
if ! dc up -d --no-build >"$UPLOG" 2>&1; then
  echo "docker compose up failed; its output:"; tail -60 "$UPLOG" | redact
  fail "compose up"
fi
rm -f "$UPLOG"
for i in $(seq 1 60); do
  [ "$(dc ps api --format '{{.Health}}')" = "healthy" ] && break; sleep 2
done
[ "$(dc ps api --format '{{.Health}}')" = "healthy" ] || fail "api not healthy"
dc logs app-init --no-color | grep "applied: 0001, 0002, 0003" >/dev/null || fail "migrations not applied on fresh install"
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
echo "ok   Trivy import via API + job-worker: $ST; cases visible: $NC"
dc up -d --no-build --force-recreate db-init app-init >/dev/null 2>&1
for i in $(seq 1 60); do   # wait for the recreated one-shot container to finish (no fixed sleep)
  [ "$(dc ps -a app-init --format '{{.State}}')" = "exited" ] && break; sleep 2
done
[ "$(dc ps -a app-init --format '{{.State}} {{.ExitCode}}')" = "exited 0" ] || fail "re-init did not exit cleanly"
dc logs app-init --no-color | grep "already seeded" >/dev/null || fail "re-init not idempotent"
dc logs app-init --no-color | grep "applied: none" >/dev/null || fail "re-migration applied something"
echo "ok   re-running init: migrations 'applied: none', seed 'already seeded'"
# --- analyst UI through the local Keycloak (checkpoint 6)
for i in $(seq 1 90); do
  [ "$(dc ps keycloak --format '{{.Health}}')" = "healthy" ] && break; sleep 2
done
[ "$(dc ps keycloak --format '{{.Health}}')" = "healthy" ] || fail "keycloak not healthy"
dc logs idp-init --no-color | grep '"alice"' >/dev/null || fail "idp-init did not link alice"
UIOUT=$(AXIOM_DEMO_PASSWORD="$DEMO_PASSWORD" uv run --frozen python "$ROOT/scripts/verify/compose_ui_check.py" \
  "http://127.0.0.1:$PORT" 2>&1) || { echo "browser check output:"; echo "$UIOUT" | redact | tail -80
                                      fail "UI check"; }
echo "$UIOUT" | grep '^ok ' | redact
UICASE=$(echo "$UIOUT" | sed -n 's/^CASE //p')
WHO=$(dc exec -T postgres psql -U postgres -d axiom -tAc "SELECT p.display_name || ' ' || p.kind FROM axiom.decisions d JOIN axiom.principals p ON p.id = d.actor_principal_id WHERE d.case_id = '$UICASE' AND d.kind = 'investigation_start'")
[ "$WHO" = "alice human" ] || fail "UI decision recorded for '$WHO'"
echo "ok   the server recorded that decision as alice's (human principal, resolved from the Keycloak subject)"
# --- production settings refuse the development configuration and fail closed
OUT=$(dc run --rm --no-deps -T -e AXIOM_ENV=production api 2>&1) && fail "production start with development identity succeeded"
echo "$OUT" | grep -q "inline JWKS is not permitted in production" || fail "production refusal reason: $(echo "$OUT" | tail -3)"
echo "ok   AXIOM_ENV=production with the development identity refuses to start (inline JWKS not permitted)"
OUT=$(dc run --rm --no-deps -T -e AXIOM_OIDC_CLIENT_SECRET= api 2>&1) && fail "start without the client secret succeeded"
echo "$OUT" | grep -q "secret reference did not resolve" || fail "missing-secret refusal reason: $(echo "$OUT" | tail -3)"
echo "ok   a missing OIDC client secret stops start-up (fails closed)"
echo "SMOKE PASS ($P)"
