#!/usr/bin/env bash
# Reproducible foundation verification on a SEPARATE disposable PostgreSQL cluster
# and a fresh SeaweedFS container. Writes a log to $OUT (default .var/verify/<timestamp>).
#
#   scripts/verify/foundation.sh
#
# Steps: record versions; init a fresh cluster; provision roles twice (idempotency);
# create database 1, migrate, re-migrate; create database 2 in the same cluster and migrate;
# reject an edited migration via the runner; run the complete pytest suite (including S3
# tests) against this cluster; tear everything down.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$ROOT/.var/verify/$STAMP}"
mkdir -p "$OUT"
export AXIOM_TEST_PGDATA=/var/tmp/axiom-verify-pg-$STAMP AXIOM_TEST_PGPORT=55433 AXIOM_TEST_PGSOCK=/var/tmp/axiom-verify-sock-$STAMP
export AXIOM_TEST_ENV_FILE="$OUT/env.test"
SW=axiom-verify-sw-$STAMP
LOG="$OUT/verify.log"
step() { echo; echo "=== $* ($(date -u +%H:%M:%SZ))"; }
{
step "versions"
echo "git HEAD: $(git rev-parse HEAD 2>/dev/null) dirty=$(git status --porcelain | wc -l)"
python3 --version; uv --version; "${PG_BIN:-/usr/lib/postgresql/16/bin}/postgres" --version
docker --version; docker compose version
uv run --frozen python -c "import fastapi,psycopg,psycopg_pool,pydantic,jwt,boto3,pytest;print('fastapi',fastapi.__version__,'psycopg',psycopg.__version__,'psycopg_pool',psycopg_pool.__version__,'pydantic',pydantic.__version__,'pyjwt',jwt.__version__,'boto3',boto3.__version__,'pytest',pytest.__version__)"

step "fresh cluster + role provisioning (first run)"
scripts/dev/test-db.sh start || exit 1
step "role provisioning (second run, idempotency)"
scripts/dev/test-db.sh start || exit 1
set -a; . "$AXIOM_TEST_ENV_FILE"; set +a
ADMIN="$AXIOM_TEST_ADMIN_DSN"
mkdb() {
  psql "$ADMIN" -X -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE $1 OWNER axiom_owner" \
    -c "REVOKE ALL ON DATABASE $1 FROM PUBLIC" \
    -c "GRANT CONNECT ON DATABASE $1 TO axiom_migrator, axiom_app, axiom_relay_app, axiom_admin_cli"
}
mig() { uv run --frozen python -m axiom.migrate --dsn "host=127.0.0.1 port=$AXIOM_TEST_PORT dbname=$1 user=axiom_migrator password=$AXIOM_TEST_MIGRATOR_PASSWORD"; }
step "database 1: create, migrate, migrate again"
mkdb axiom_verify_one && mig axiom_verify_one && mig axiom_verify_one
step "database 2 in the same cluster: create, migrate"
mkdb axiom_verify_two && mig axiom_verify_two
step "edited migration is rejected by the CLI runner"
TMPM="$(mktemp -d)"; cp -r backend/axiom/migrations "$TMPM/m"; echo "-- edited" >> "$TMPM/m/0001_foundation.sql"
uv run --frozen python -c "
import sys; from pathlib import Path; from axiom import migrate
try:
    migrate.apply(sys.argv[1], directory=Path(sys.argv[2])); print('UNEXPECTED: edited migration accepted'); sys.exit(1)
except migrate.MigrationError as e: print('rejected as expected:', e)
" "host=127.0.0.1 port=$AXIOM_TEST_PORT dbname=axiom_verify_two user=axiom_migrator password=$AXIOM_TEST_MIGRATOR_PASSWORD" "$TMPM/m"
rm -rf "$TMPM"
step "RLS structural audit as runtime role (database 2)"
psql "host=127.0.0.1 port=$AXIOM_TEST_PORT dbname=axiom_verify_two user=axiom_app password=$AXIOM_TEST_APP_PASSWORD" -X -A -F ' ' -c "
SELECT count(*) FILTER (WHERE relrowsecurity AND relforcerowsecurity) AS forced_rls,
       count(*) FILTER (WHERE NOT relrowsecurity) AS no_rls,
       string_agg(relname, ',') FILTER (WHERE NOT relrowsecurity) AS no_rls_tables,
       count(*) FILTER (WHERE pg_get_userbyid(relowner) <> 'axiom_owner') AS not_owner_owned
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='axiom' AND c.relkind='r';" \
 -c "SELECT current_user, rolsuper, rolbypassrls, pg_has_role(current_user,'axiom_owner','MEMBER') AS owner_member FROM pg_roles WHERE rolname=current_user;"

step "fresh SeaweedFS for S3 tests"
CFG="$OUT/sw"; mkdir -p "$CFG"
AK=$(python3 -c 'import secrets;print(secrets.token_hex(8))'); SK=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
printf '{"identities":[{"name":"axiom","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read","Write","List","Tagging","Admin"]}]}' "$AK" "$SK" > "$CFG/s3.json"
docker run -d --name "$SW" -p 127.0.0.1:18334:8333 -v "$CFG":/cfg:ro \
  mirror.gcr.io/chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d \
  server -s3 -s3.config=/cfg/s3.json -dir=/data >/dev/null
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AXIOM_TEST_S3_ENDPOINT=http://127.0.0.1:18334 AXIOM_TEST_S3_BUCKET=axiom-verify
for i in $(seq 1 30); do
  uv run --frozen python -c "import boto3;c=boto3.client('s3',endpoint_url='$AXIOM_TEST_S3_ENDPOINT',region_name='us-east-1');c.create_bucket(Bucket='axiom-verify')" >/dev/null 2>&1 && { echo "bucket created after ${i} attempt(s)"; break; }
  sleep 2
done

step "complete pytest suite (unit + PostgreSQL + S3), fresh session database"
uv run --frozen pytest tests -v -rA -p no:cacheprovider 2>&1 | grep -v UV_NATIVE
echo "pytest exit=${PIPESTATUS[0]}"

step "teardown"
docker rm -f "$SW" >/dev/null && echo "seaweedfs removed"
scripts/dev/test-db.sh destroy >/dev/null 2>&1; echo "cluster destroyed"; rm -rf "$AXIOM_TEST_PGSOCK"
} 2>&1 | grep -v "UV_NATIVE_TLS" | tee "$LOG"
rm -f "$AXIOM_TEST_ENV_FILE"   # contains generated passwords for the destroyed cluster
echo "log: $LOG"
