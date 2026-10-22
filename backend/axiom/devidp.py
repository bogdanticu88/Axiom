"""Local identity provider for the Compose development profile (Keycloak), with SYNTHETIC users only.

    python -m axiom.devidp realm --out DIR      # write DIR/realm.json for Keycloak's --import-realm
    python -m axiom.devidp link --admin-dsn DSN # map the Keycloak users to the seeded platform principals

The realm holds one confidential client (``axiom-ui``, authorization code flow with PKCE S256 only) and one user
per seeded person (see axiom.devseed). Secrets come from the environment and are never written to the repository:
``AXIOM_OIDC_CLIENT_SECRET`` (the client secret) and ``AXIOM_DEMO_PASSWORD`` (one password shared by the synthetic users).
Keycloak user IDs are derived deterministically from the user name, so the mapping survives re-running the init.

``link`` records, for each seeded person, a federated identity (issuer, client id, Keycloak subject) pointing at the
principal the seed created. Identity is by issuer and subject; email is not used. Both commands refuse to run when
AXIOM_ENV=production: this is not a production identity configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .devtools import DEV_AUDIENCE, DEV_ISSUER
from .provisioning import Provisioner

REALM = "axiom"
CLIENT_ID = "axiom-ui"
USERS = ("alice", "carol", "bob", "dave", "erin", "admin", "audrey", "consult")
NAMESPACE = uuid.UUID("6f0c2e8e-4c55-4d0b-9a7e-0c7b1d3d5a11")   # fixed: keeps user IDs stable across re-inits


def subject_for(username: str) -> str:
    return str(uuid.uuid5(NAMESPACE, username))


def _refuse_production() -> None:
    if os.environ.get("AXIOM_ENV") == "production":
        raise SystemExit("refusing to configure the development identity provider in production")


def _need(name: str) -> str:
    value = os.environ.get(name)
    if not value or len(value) < 12:
        raise SystemExit(f"{name} must be set (at least 12 characters)")
    return value


def realm(public_origin: str) -> dict:
    secret, password = _need("AXIOM_OIDC_CLIENT_SECRET"), _need("AXIOM_DEMO_PASSWORD")
    origin = public_origin.rstrip("/")
    return {
        "realm": REALM, "enabled": True, "sslRequired": "none", "accessTokenLifespan": 300,
        "loginWithEmailAllowed": False, "registrationAllowed": False, "resetPasswordAllowed": False,
        "clients": [{
            "clientId": CLIENT_ID, "protocol": "openid-connect", "publicClient": False, "secret": secret,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
            "serviceAccountsEnabled": False, "redirectUris": [f"{origin}/auth/callback"],
            "webOrigins": [], "attributes": {"pkce.code.challenge.method": "S256",
                                             "post.logout.redirect.uris": f"{origin}/ui/"}}],
        "users": [{"id": subject_for(u), "username": u, "enabled": True, "email": f"{u}@example.invalid",
                   "emailVerified": True, "firstName": u.title(), "lastName": "Synthetic",
                   "credentials": [{"type": "password", "value": password, "temporary": False}]} for u in USERS],
    }


def link(admin_dsn: str, issuer: str) -> dict:
    p = Provisioner(admin_dsn)
    provider = p.ensure_identity_provider(issuer.rstrip("/"), CLIENT_ID)
    with psycopg.connect(admin_dsn, row_factory=dict_row) as conn:
        dev = conn.execute("SELECT id FROM axiom.identity_providers WHERE issuer = %s AND audience = %s",
                           (DEV_ISSUER, DEV_AUDIENCE)).fetchone()
        if dev is None:
            raise SystemExit("seed the installation first (python -m axiom.devseed)")
        linked = {}
        for u in USERS:
            row = conn.execute("SELECT principal_id FROM axiom.federated_identities WHERE provider_id = %s AND subject = %s",
                               (dev["id"], u)).fetchone()
            if row is None:
                continue
            conn.execute("""INSERT INTO axiom.federated_identities(provider_id, subject, principal_id)
                            VALUES (%s, %s, %s) ON CONFLICT (provider_id, subject) DO NOTHING""",
                         (provider, subject_for(u), row["principal_id"]))
            linked[u] = str(row["principal_id"])
    return {"provider_id": str(provider), "issuer": issuer, "linked": linked}


def main() -> int:
    _refuse_production()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("realm")
    r.add_argument("--out", required=True)
    r.add_argument("--public-origin", default=os.environ.get("AXIOM_PUBLIC_ORIGIN", "http://127.0.0.1:8000"))
    lk = sub.add_parser("link")
    lk.add_argument("--admin-dsn", required=True)
    lk.add_argument("--issuer", default=os.environ.get("AXIOM_OIDC_ISSUER"))
    args = parser.parse_args()
    if args.cmd == "realm":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        target = out / "realm.json"
        target.write_text(json.dumps(realm(args.public_origin)))
        target.chmod(0o644)       # read by the Keycloak container user; holds synthetic credentials only
        print(f"realm written for {args.public_origin}")
    else:
        if not args.issuer:
            raise SystemExit("--issuer or AXIOM_OIDC_ISSUER is required")
        print(json.dumps(link(args.admin_dsn, args.issuer), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
