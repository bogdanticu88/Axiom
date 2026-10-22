"""Enterprise sign-in (ADR 0013) against a local Keycloak: protocol path, callback protections, sessions, logout,
membership revocation, and refusal of development tokens in production.

Not covered: Microsoft Entra ID or any hosted IdP (never tested); back-channel logout from the IdP.
"""
from __future__ import annotations

import json
import os
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from axiom.api.app import create_app
from axiom.config import Settings, TrustedIssuer
from axiom.errors import ConfigurationError, Unauthenticated

from .oidc_support import CLIENT_ID, LiveServer, browserless_login, keycloak, provision  # noqa: F401

pytestmark = pytest.mark.db


@pytest.fixture()
def server(keycloak, dbinfo, db, object_store, issuer, world):  # noqa: F811
    settings = Settings(env="test", database_dsn=dbinfo.app_dsn, trusted_issuers_json=json.dumps(
        [{"issuer": issuer.issuer, "audience": issuer.audience, "jwks": issuer.jwks()}]),
        oidc_issuer=keycloak.issuer, oidc_client_id=CLIENT_ID,
        oidc_client_secret_ref=f"secretref:env/{keycloak.client_secret_env}",
        oidc_redirect_uri=keycloak.redirect_uri, ui_cookie_secure=False,
        oidc_post_logout_redirect_uri=f"http://127.0.0.1:{keycloak.api_port}/ui/")
    app = create_app(settings, db=db, store=object_store)
    with LiveServer(app, keycloak.api_port) as live:
        yield live


def api(c: httpx.Client, base: str, method: str, path: str, tenant, **kw):
    headers = {"X-Axiom-Tenant": tenant.slug}
    if method != "GET":
        headers["X-CSRF-Token"] = c.cookies.get("axiom_csrf", "")
    return c.request(method, f"{base}/api/v1{path}", headers={**headers, **kw.pop("headers", {})}, **kw)


def test_login_creates_a_session_and_tenant_access_is_checked_per_request(server, keycloak, dbinfo, world):
    provision(dbinfo, world, keycloak, who={"alice": ("a", [("analyst", "project")])})
    c, r = browserless_login(server.base, keycloak, "alice", return_to="/ui/cases")
    assert r.status_code == 303 and r.headers["location"] == "/ui/cases"
    set_cookies = r.headers.get_list("set-cookie")
    session_cookie = [x for x in set_cookies if x.startswith("axiom_session=")][0]
    assert "HttpOnly" in session_cookie and "SameSite=lax" in session_cookie
    assert "HttpOnly" not in [x for x in set_cookies if x.startswith("axiom_csrf=")][0]   # readable for the header
    info = c.get(f"{server.base}/auth/session").json()
    assert [t["tenant_id"] for t in info["tenants"]] == [str(world.a.id)]
    assert api(c, server.base, "GET", "/cases", world.a).status_code == 200
    assert api(c, server.base, "GET", "/cases", world.b).status_code == 403          # not a member of tenant B
    ok = api(c, server.base, "POST", "/cases", world.a, json={"scope_id": str(world.a.project), "title": "t"})
    assert ok.status_code == 201
    no_csrf = c.post(f"{server.base}/api/v1/cases", headers={"X-Axiom-Tenant": world.a.slug},
                     json={"scope_id": str(world.a.project), "title": "t"})
    assert no_csrf.status_code == 403 and no_csrf.json()["error"]["code"] == "csrf_failed"
    wrong = api(c, server.base, "POST", "/cases", world.a, headers={"X-CSRF-Token": "x" * 43},
                json={"scope_id": str(world.a.project), "title": "t"})
    assert wrong.status_code == 403


def test_callback_protections(server, keycloak, dbinfo, world):
    provision(dbinfo, world, keycloak, who={"alice": ("a", [("analyst", "project")])})
    # 1. a callback replayed after use is refused
    c, callback = browserless_login(server.base, keycloak, "alice", stop_before_callback=True)
    binding = c.cookies.get("axiom_login")          # the callback clears it; an attacker who copied it keeps it
    assert c.get(callback).status_code == 303
    replay = httpx.get(callback, headers={"Cookie": f"axiom_login={binding}"}, follow_redirects=False)
    # refused by the platform's single-use state, before any code exchange (not merely by the IdP's code reuse rule)
    assert replay.status_code == 401 and "already used" in replay.json()["error"]["message"]
    # 2. a callback delivered to another browser (no login-binding cookie) is refused: login CSRF / fixation
    c2, callback2 = browserless_login(server.base, keycloak, "alice", stop_before_callback=True)
    other = httpx.Client(follow_redirects=False)
    elsewhere = other.get(callback2)                                                   # no binding cookie at all
    assert elsewhere.status_code == 401 and "incomplete" in elsewhere.json()["error"]["message"]
    forged = httpx.get(callback2, headers={"Cookie": "axiom_login=" + "x" * 43}, follow_redirects=False)
    assert forged.status_code == 401 and "another browser" in forged.json()["error"]["message"]
    # 3. tampered state, mismatched issuer parameter, IdP error, missing code
    c3, callback3 = browserless_login(server.base, keycloak, "alice", stop_before_callback=True)
    q = parse_qs(urlparse(callback3).query)
    base_cb = keycloak.redirect_uri
    assert c3.get(base_cb, params={"code": q["code"][0], "state": "tampered"}).status_code == 401
    assert c3.get(base_cb, params={"code": q["code"][0], "state": q["state"][0],
                                   "iss": "http://evil.example/realms/x"}).status_code == 401
    assert c3.get(base_cb, params={"error": "access_denied", "state": q["state"][0]}).status_code == 401
    assert c3.get(base_cb, params={"state": q["state"][0]}).status_code == 401
    # 4. open redirect attempts land on the UI root
    c4, r = browserless_login(server.base, keycloak, "alice", return_to="https://evil.example/x")
    assert r.headers["location"] == "/ui/"
    c5, r = browserless_login(server.base, keycloak, "alice", return_to="//evil.example/ui")
    assert r.headers["location"] == "/ui/"


def test_identity_is_issuer_and_subject_not_email(server, keycloak, dbinfo, world):
    ids = provision(dbinfo, world, keycloak, who={"alice": ("a", [("analyst", "project")])})
    # mallory has the same email address as alice but a different subject: refused, never merged into alice
    c, r = browserless_login(server.base, keycloak, "mallory")
    assert r.status_code == 403 and r.json()["error"]["code"] == "identity_not_provisioned"
    c, r = browserless_login(server.base, keycloak, "alice")
    assert c.get(f"{server.base}/auth/session").json()["principal_id"] == str(ids["alice"])


def test_logout_revokes_the_session(server, keycloak, dbinfo, world):
    provision(dbinfo, world, keycloak, who={"alice": ("a", [("analyst", "project")])})
    c, _ = browserless_login(server.base, keycloak, "alice")
    stolen = c.cookies.get("axiom_session")
    assert c.post(f"{server.base}/auth/logout").status_code == 403                  # needs the CSRF header
    r = c.post(f"{server.base}/auth/logout", headers={"X-CSRF-Token": c.cookies.get("axiom_csrf")})
    assert r.status_code == 200 and r.json()["end_session_url"].startswith(keycloak.issuer)
    assert "client_id=" + CLIENT_ID in r.json()["end_session_url"]
    replay = httpx.Client(cookies={"axiom_session": stolen})
    assert replay.get(f"{server.base}/auth/session").status_code == 401             # revoked server-side


def test_membership_and_role_revocation_take_effect_on_the_next_request(server, keycloak, dbinfo, world, run,
                                                                         ctx_for):
    ids = provision(dbinfo, world, keycloak, who={"bob": ("a", [("analyst", "project")])})
    c, _ = browserless_login(server.base, keycloak, "bob")
    assert api(c, server.base, "GET", "/cases", world.a).status_code == 200
    body = {"scope_id": str(world.a.project), "title": "before revocation"}
    assert api(c, server.base, "POST", "/cases", world.a, json=body).status_code == 201
    # role revoked during the active session: the same session's next command is refused
    for b in run(ctx_for("admin"), lambda s: s.conn.execute(
            "SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL", (ids["bob"],)).fetchall()):
        run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=b["id"], reason="moved team"))
    r = api(c, server.base, "POST", "/cases", world.a, json=body)
    assert r.status_code == 403 and r.json()["error"]["code"] == "permission_denied"
    assert c.get(f"{server.base}/auth/session").status_code == 200       # still signed in, with no authority
    run(ctx_for("admin"), lambda s: s.tenancy.suspend_membership(principal_id=ids["bob"], reason="left"))
    r = api(c, server.base, "GET", "/cases", world.a)
    assert r.status_code == 403 and r.json()["error"]["code"] == "tenant_not_available"


def test_session_expiry_and_disabled_principal(server, keycloak, dbinfo, world, admin_conn):
    ids = provision(dbinfo, world, keycloak, who={"alice": ("a", [("analyst", "project")])})
    c, _ = browserless_login(server.base, keycloak, "alice")
    admin_conn.execute("UPDATE axiom.ui_sessions SET last_seen_at = clock_timestamp() - interval '2 hours' "
                       "WHERE principal_id = %s", (ids["alice"],))                   # fault injection: idle
    assert c.get(f"{server.base}/auth/session").status_code == 401
    c, _ = browserless_login(server.base, keycloak, "alice")
    admin_conn.execute("UPDATE axiom.principals SET status = 'disabled' WHERE id = %s", (ids["alice"],))
    assert c.get(f"{server.base}/auth/session").status_code == 401


# ---------------------------------------------------------------------------- development tokens in production
def test_production_refuses_development_tokens_at_startup_and_runtime(issuer):
    dev = [{"issuer": issuer.issuer, "audience": issuer.audience, "jwks": issuer.jwks()}]
    with pytest.raises(ConfigurationError):
        Settings(env="production", database_dsn="postgresql://x", object_store="s3", s3_bucket="b",
                 trusted_issuers_json=json.dumps(dev)).validate_for_runtime()
    from axiom.auth.tokens import TokenVerifier
    verifier = TokenVerifier([TrustedIssuer.model_validate(dev[0])], env="production")
    with pytest.raises(Unauthenticated) as err:
        verifier.verify(issuer.token("someone"))
    assert "disabled in production" in str(err.value)
    assert TokenVerifier([TrustedIssuer.model_validate(dev[0])], env="test").verify(issuer.token("someone"))


def test_production_sso_settings_are_checked():
    base = dict(env="production", database_dsn="postgresql://x", object_store="s3", s3_bucket="b",
                trusted_issuers_json=json.dumps([{"issuer": "https://idp.example", "audience": "a",
                                                  "jwks_uri": "https://idp.example/jwks"}]),
                oidc_client_id="c", oidc_client_secret_ref="secretref:env/X",
                oidc_redirect_uri="https://axiom.example/auth/callback")
    for bad in ({"oidc_issuer": "http://idp.example"}, {"oidc_issuer": "https://idp.example", "ui_cookie_secure": False},
                {"oidc_issuer": "https://idp.example", "oidc_client_secret_ref": "plain-secret-value"}):
        with pytest.raises(ConfigurationError):
            Settings(**{**base, **bad}).validate_for_runtime()
    Settings(**{**base, "oidc_issuer": "https://idp.example"}).validate_for_runtime()
    _ = os
