#!/bin/sh
# Provision cluster roles and the application database. Idempotent.
set -eu
until pg_isready -q; do sleep 1; done
PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 \
  -v migrator_password="$AXIOM_MIGRATOR_PASSWORD" -v app_password="$AXIOM_APP_PASSWORD" \
  -v relay_password="$AXIOM_RELAY_PASSWORD" -v admin_cli_password="$AXIOM_ADMIN_CLI_PASSWORD" \
  -f /axiom/db/provision_roles.sql
if ! psql -X -tAc "SELECT 1 FROM pg_database WHERE datname = 'axiom'" | grep -q 1; then
  psql -X -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE axiom OWNER axiom_owner"
fi
psql -X -q -v ON_ERROR_STOP=1 -c "REVOKE ALL ON DATABASE axiom FROM PUBLIC" \
  -c "GRANT CONNECT ON DATABASE axiom TO axiom_migrator, axiom_app, axiom_relay_app, axiom_admin_cli"
echo "db-init complete"
