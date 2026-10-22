"""Seed a development installation with SYNTHETIC tenants and users.

Idempotent: does nothing if the 'demo' tenant exists. Uses the development
issuer from axiom.devtools; refuses to run when AXIOM_ENV=production.

Users (subject -> roles in tenant 'demo', project 'payments'):
  alice    analyst            carol  analyst (independent verifier)
  bob      remediation_owner  dave   approver
  erin     risk_owner (limit: up to 'high', 90 days)
  admin    tenant_admin (root)   audrey auditor (root)
  consult  analyst in 'demo' and in 'demo-two' (multi-tenant consultant)
"""
from __future__ import annotations

import argparse
import json
import os

import psycopg

from .devtools import DEV_AUDIENCE, DEV_ISSUER
from .provisioning import Provisioner


def seed(admin_dsn: str, app_dsn: str) -> dict:
    if os.environ.get("AXIOM_ENV") == "production":
        raise SystemExit("refusing to seed synthetic data in production")
    p = Provisioner(admin_dsn)
    with psycopg.connect(admin_dsn) as conn:
        if conn.execute("SELECT 1 FROM axiom.tenants WHERE slug = 'demo'").fetchone():
            return {"status": "already seeded"}
    installation = p.ensure_installation("shared", "local")
    provider = p.ensure_identity_provider(DEV_ISSUER, DEV_AUDIENCE)
    demo = p.create_tenant(installation, "demo", "Demo Client (synthetic)")
    two = p.create_tenant(installation, "demo-two", "Second Demo Client (synthetic)")
    payments = p.create_scope(demo.tenant_id, demo.root_scope_id, "project", "payments")
    payments_two = p.create_scope(two.tenant_id, two.root_scope_id, "project", "payments")
    people = {}
    plan = {"alice": [("analyst", payments)], "carol": [("analyst", payments)],
            "bob": [("remediation_owner", payments)], "dave": [("approver", payments)],
            "erin": [("risk_owner", payments)], "admin": [("tenant_admin", demo.root_scope_id)],
            "audrey": [("auditor", demo.root_scope_id)], "consult": [("analyst", payments)]}
    for subject, roles in plan.items():
        pid = p.create_principal(subject, provider_id=provider, subject=subject)
        people[subject] = str(pid)
        p.add_membership(demo.tenant_id, pid)
        for role, scope in roles:
            p.bootstrap_role(demo.tenant_id, pid, role, scope, "development seed (synthetic)")
    p.add_membership(two.tenant_id, people["consult"])
    p.bootstrap_role(two.tenant_id, people["consult"], "analyst", payments_two, "development seed (synthetic)")
    # Erin's delegation limit. The tenant admin API would need a token, so the seed writes it directly,
    # through the runtime role bound to the admin principal.
    with psycopg.connect(app_dsn) as conn:
        with conn.transaction():
            conn.execute("SELECT axiom.bind_context(%s, %s)", (demo.tenant_id, people["admin"]))
            conn.execute(
                """INSERT INTO axiom.delegation_limits(tenant_id, id, principal_id, action_class, scope_id,
                       max_priority, max_duration_days, created_by)
                   VALUES (%s, gen_random_uuid(), %s, 'risk.accept', %s, 'high', 90, %s)""",
                (demo.tenant_id, people["erin"], payments, people["admin"]))
    return {"status": "seeded", "tenants": {"demo": str(demo.tenant_id), "demo-two": str(two.tenant_id)},
            "scopes": {"demo/payments": str(payments)}, "principals": people}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-dsn", required=True)
    parser.add_argument("--app-dsn", required=True)
    args = parser.parse_args()
    print(json.dumps(seed(args.admin_dsn, args.app_dsn), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
