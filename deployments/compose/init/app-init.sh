#!/bin/sh
# Migrations, development identity, synthetic seed and evidence bucket. Idempotent.
set -eu
chown 10001 /var/lib/axiom/dev-idp
exec setpriv --reuid=10001 --regid=10001 --clear-groups sh -eu -c '
python -m axiom.migrate --dsn "$AXIOM_MIGRATOR_DSN"
if [ ! -f /var/lib/axiom/dev-idp/private.pem ]; then python -m axiom.devtools keygen --dir /var/lib/axiom/dev-idp; fi
python -m axiom.devtools issuer-config --dir /var/lib/axiom/dev-idp > /var/lib/axiom/dev-idp/issuers.json
python -m axiom.devseed --admin-dsn "$AXIOM_ADMIN_DSN" --app-dsn "$AXIOM_APP_DSN_SEED"
python - <<PY
import os, time, boto3
c = boto3.client("s3", endpoint_url=os.environ["AXIOM_S3_ENDPOINT_URL"], region_name="us-east-1")
for attempt in range(60):
    try:
        names = [b["Name"] for b in c.list_buckets()["Buckets"]]
        if os.environ["AXIOM_S3_BUCKET"] not in names:
            c.create_bucket(Bucket=os.environ["AXIOM_S3_BUCKET"])
        print("bucket ready"); break
    except Exception as exc:
        time.sleep(2)
else:
    raise SystemExit("object storage not reachable")
PY
echo "app-init complete"
'
