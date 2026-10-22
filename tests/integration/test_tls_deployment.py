"""The documented deployment, built locally over TLS (docs/DEPLOYMENT-TRUST-BOUNDARY.md).

What runs: an nginx reverse proxy (pinned image) terminating TLS with a certificate from a throwaway local CA, in front
of the API (production settings, OIDC client secret from a mounted file, forwarding headers ignored) and of a local
Keycloak 26.4.2 that knows its public HTTPS address. Chromium trusts exactly that certificate (pinned by its public
key), not every certificate. This establishes local deployment behaviour only: no hosted identity provider, public
network, real certificate authority or provider interoperability is involved. The object store is the test
filesystem store; it is not what this module tests.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from axiom.errors import ConfigurationError

from .oidc_support import CLIENT_ID, KEYCLOAK_IMAGE, REALM, User, free_port, provision
from .test_analyst_ui import DIST, shot

pytestmark = pytest.mark.db
NGINX_IMAGE = ("mirror.gcr.io/library/nginx:1.29.2-alpine@sha256:"
               "61e01287e546aac28a3f56839c136b31f590273f3b41187a36f46f6a03bbfe22")


def _require(ok: bool, why: str):
    if not ok:
        (pytest.fail if os.environ.get("AXIOM_REQUIRE_UI") == "1" else pytest.skip)(why)


def _pki(d: Path):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axiom local TLS test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (d / "leaf.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    spki = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


NGINX_CONF = """
events {{}}
http {{
  access_log off;
  ssl_protocols TLSv1.2 TLSv1.3;
  # the platform: forwarding headers a client sends are dropped, as docs/DEPLOYMENT-TRUST-BOUNDARY.md asks
  server {{
    listen 127.0.0.1:{app} ssl;
    ssl_certificate /certs/leaf.pem; ssl_certificate_key /certs/leaf.key;
    location / {{
      proxy_pass http://127.0.0.1:{api};
      proxy_set_header Host $host:$server_port;
      proxy_set_header X-Forwarded-For ""; proxy_set_header X-Forwarded-Host "";
      proxy_set_header X-Forwarded-Proto ""; proxy_set_header Forwarded "";
    }}
  }}
  # the identity provider: Keycloak is told its public address by the proxy
  server {{
    listen 127.0.0.1:{idp} ssl;
    ssl_certificate /certs/leaf.pem; ssl_certificate_key /certs/leaf.key;
    location / {{
      proxy_pass http://127.0.0.1:{kc};
      proxy_set_header Host $host:$server_port;
      proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-Host $host:$server_port;
      proxy_set_header X-Forwarded-Port $server_port; proxy_set_header X-Forwarded-For $remote_addr;
    }}
  }}
}}
"""


def _wait(url, ca, seconds=180, ok=(200,)):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if httpx.get(url, verify=ssl.create_default_context(cafile=str(ca)), timeout=2).status_code in ok:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError(f"{url} did not become ready")


@pytest.fixture(scope="module")
def tls():
    _require(shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0,
             "Docker is not available for the local TLS deployment")
    _require((DIST / "index.html").is_file(), f"analyst UI is not built at {DIST}")
    d = Path(tempfile.mkdtemp(prefix="axiom-tls-"))
    certs, secrets_dir, kc_import = d / "certs", d / "run-secrets", d / "kc"
    for p in (certs, secrets_dir, kc_import):
        p.mkdir()
    spki = _pki(certs)
    app_port, idp_port, kc_port, api_port = free_port(), free_port(), free_port(), free_port()
    origin, idp_origin = f"https://localhost:{app_port}", f"https://localhost:{idp_port}"
    client_secret = secrets.token_urlsafe(32)
    users = {n: User(n, secrets.token_urlsafe(18), str(uuid.uuid4()), f"{n}@example.test") for n in ("alice", "bob")}
    (kc_import / "realm.json").write_text(json.dumps({
        "realm": REALM, "enabled": True, "sslRequired": "external", "accessTokenLifespan": 300,
        "clients": [{"clientId": CLIENT_ID, "protocol": "openid-connect", "publicClient": False, "secret": client_secret,
                     "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                     "redirectUris": [f"{origin}/auth/callback"],
                     "attributes": {"pkce.code.challenge.method": "S256",
                                    "post.logout.redirect.uris": f"{origin}/ui/"}}],
        "users": [{"id": u.sub, "username": u.username, "enabled": True, "email": u.email, "emailVerified": True,
                   "firstName": u.username.title(), "lastName": "Test",
                   "credentials": [{"type": "password", "value": u.password, "temporary": False}]}
                  for u in users.values()]}))
    (secrets_dir / "oidc-client-secret").write_text(client_secret + "\n")
    os.chmod(secrets_dir / "oidc-client-secret", 0o400)
    (d / "nginx.conf").write_text(NGINX_CONF.format(app=app_port, api=api_port, idp=idp_port, kc=kc_port))
    for p in (d, certs, kc_import):
        os.chmod(p, 0o755)
    for f in ("ca.pem", "leaf.pem", "leaf.key"):
        os.chmod(certs / f, 0o644)
    os.chmod(kc_import / "realm.json", 0o644)
    os.chmod(d / "nginx.conf", 0o644)
    tag = uuid.uuid4().hex[:8]
    kc_name, px_name = f"axiom-tls-kc-{tag}", f"axiom-tls-proxy-{tag}"
    try:
        subprocess.run(["docker", "run", "-d", "--name", kc_name, "-p", f"127.0.0.1:{kc_port}:8080",
                        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap",
                        "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(18)}",
                        "-v", f"{kc_import}:/opt/keycloak/data/import:ro", KEYCLOAK_IMAGE, "start-dev",
                        "--import-realm", f"--hostname={idp_origin}", "--proxy-headers=xforwarded",
                        "--http-enabled=true"], check=True, capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", px_name, "--network", "host",
                        "-v", f"{d / 'nginx.conf'}:/etc/nginx/nginx.conf:ro", "-v", f"{certs}:/certs:ro", NGINX_IMAGE],
                       check=True, capture_output=True)
        _wait(f"{idp_origin}/realms/{REALM}/.well-known/openid-configuration", certs / "ca.pem")
        yield {"dir": d, "ca": certs / "ca.pem", "spki": spki, "origin": origin, "idp": idp_origin,
               "issuer": f"{idp_origin}/realms/{REALM}", "api_port": api_port, "users": users,
               "secret_file": secrets_dir / "oidc-client-secret", "secrets_dir": secrets_dir,
               "client_secret": client_secret}
    finally:
        subprocess.run(["docker", "rm", "-f", kc_name, px_name], capture_output=True)
        shutil.rmtree(d, ignore_errors=True)


def production_settings(t, dbinfo, **over):
    from axiom.config import Settings
    base = dict(env="production", database_dsn=dbinfo.app_dsn,
                trusted_issuers_json=json.dumps([{"issuer": t["issuer"], "audience": CLIENT_ID,
                                                  "jwks_uri": f"{t['issuer']}/protocol/openid-connect/certs"}]),
                object_store="s3", s3_bucket="unused-by-this-test", s3_endpoint_url="https://localhost:1",
                oidc_issuer=t["issuer"], oidc_client_id=CLIENT_ID,
                oidc_client_secret_ref=f"secretref:file{t['secret_file']}", secret_file_dirs=str(t["secrets_dir"]),
                oidc_redirect_uri=f"{t['origin']}/auth/callback",
                oidc_post_logout_redirect_uri=f"{t['origin']}/ui/", ui_cookie_secure=True, ui_dist_dir=str(DIST))
    base.update(over)
    return Settings(**base)


@pytest.fixture()
def deployed(tls, dbinfo, db, object_store, world, monkeypatch):
    """The API in production mode, built the way `python -m axiom.server` builds it, behind the TLS proxy."""
    from axiom import server
    from axiom.api.app import create_app
    monkeypatch.setenv("SSL_CERT_FILE", str(tls["ca"]))          # the API trusts the local CA for IdP calls
    monkeypatch.setenv("AXIOM_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("AXIOM_PORT", str(tls["api_port"]))
    ids = provision(dbinfo, world, _IdPView(tls), who={"alice": ("a", [("analyst", "project")]),
                                                       "bob": ("a", [("viewer", "project")])})
    srv = server.build(create_app(production_settings(tls, dbinfo), db=db, store=object_store))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(200):
        if srv.started:
            break
        time.sleep(0.05)
    _wait(f"{tls['origin']}/ui/", tls["ca"], seconds=20, ok=(200,))
    try:
        yield {**tls, "ids": ids}
    finally:
        srv.should_exit = True
        th.join(10)


class _IdPView:
    """Adapter so oidc_support.provision can register this IdP's users."""
    def __init__(self, t):
        self.issuer, self.users = t["issuer"], t["users"]


def client(t, **kw):
    return httpx.Client(verify=ssl.create_default_context(cafile=str(t["ca"])), follow_redirects=False, timeout=15,
                        **kw)


def login(t, username):
    """The authorization code flow over TLS with a plain HTTP client (the browser test drives the same pages)."""
    c = client(t)
    r = c.get(f"{t['origin']}/auth/login", params={"return_to": "/ui/"})
    assert r.status_code == 302, r.text
    r = c.get(r.headers["location"])
    action = re.search(r'action="([^"]+)"', r.text).group(1).replace("&amp;", "&")
    u = t["users"][username]
    r = c.post(action, data={"username": u.username, "password": u.password, "credentialId": ""})
    assert r.status_code == 302, r.text[:500]
    callback = r.headers["location"]
    assert callback.startswith(f"{t['origin']}/auth/callback?")
    return c, c.get(callback)


# ------------------------------------------------------------------------------------------------- browser
def test_browser_sign_in_over_tls_with_secure_cookies_csrf_logout_and_replay(deployed, world, tmp_path):
    t = deployed
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _require(False, "playwright is not installed")
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            str(tmp_path / "profile"), args=[f"--ignore-certificate-errors-spki-list={t['spki']}"])
        ctx.add_init_script(f"try {{ localStorage.setItem('axiom.tenant', {json.dumps(world.a.slug)}) }} catch (e) {{}}")
        page = ctx.new_page()
        page.set_default_timeout(20_000)
        page.goto(f"{t['origin']}/ui/")
        page.get_by_test_id("sign-in").click()
        page.wait_for_url(f"{t['idp']}/**")                       # Keycloak's login page, over TLS
        page.fill("#username", "alice")
        page.fill("#password", t["users"]["alice"].password)
        page.click("#kc-login")
        page.wait_for_url(f"{t['origin']}/ui/**")
        page.get_by_test_id("sign-out").wait_for()
        assert page.url.startswith("https://")
        page.get_by_test_id("sources").wait_for()
        shot(page, "30-signed-in-over-tls")
        cookies = {c["name"]: c for c in ctx.cookies(t["origin"])}
        session, csrf = cookies["axiom_session"], cookies["axiom_csrf"]
        assert session["secure"] and session["httpOnly"] and session["sameSite"] == "Lax"
        assert csrf["secure"] and not csrf["httpOnly"]
        # CSRF: an unsafe request without the header is refused even with the session cookie
        r = page.request.post(f"{t['origin']}/api/v1/cases", headers={"X-Axiom-Tenant": world.a.slug},
                              data={"scope_id": str(world.a.project), "title": "x"})
        assert r.status == 403 and r.json()["error"]["code"] == "csrf_failed"
        r = page.request.post(f"{t['origin']}/api/v1/cases", data={"scope_id": str(world.a.project), "title": "x"},
                              headers={"X-Axiom-Tenant": world.a.slug, "X-CSRF-Token": csrf["value"]})
        assert r.status == 201
        page.get_by_test_id("sign-out").click()
        page.wait_for_url(f"{t['idp']}/**")                       # RP-initiated logout at the IdP
        shot(page, "31-logout-at-idp-over-tls")
        ctx.close()
    with client(t) as c:                                          # the old cookie is dead server-side
        r = c.get(f"{t['origin']}/auth/session", headers={"Cookie": f"axiom_session={session['value']}"})
        assert r.status_code == 401


# ------------------------------------------------------------------------------------------------- headers
SPOOFED = {"X-Forwarded-Host": "evil.test", "X-Forwarded-Proto": "http", "X-Forwarded-For": "203.0.113.9",
           "Forwarded": "host=evil.test;proto=http", "Host": "evil.test"}


@pytest.mark.parametrize("via", ["proxy", "direct"])
def test_spoofed_forwarding_and_host_headers_do_not_change_redirects(deployed, via):
    """Through the proxy, and straight to the API as someone on the private network could: the sign-in redirect and
    the callback target always use the configured external origin."""
    t = deployed
    base = t["origin"] if via == "proxy" else f"http://127.0.0.1:{t['api_port']}"
    with client(t) as c:
        r = c.get(f"{base}/auth/login", params={"return_to": "/ui/"}, headers=SPOOFED)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(f"{t['issuer']}/protocol/openid-connect/auth?")
    q = parse_qs(urlsplit(loc).query)
    assert q["redirect_uri"] == [f"{t['origin']}/auth/callback"]
    assert "evil.test" not in loc


def test_callback_and_logout_redirects_use_the_configured_origin(deployed):
    t = deployed
    c, r = login(t, "alice")
    assert r.status_code == 303 and r.headers["location"] == "/ui/"          # relative: same origin
    set_cookies = r.headers.get_list("set-cookie")
    sess = [x for x in set_cookies if x.startswith("axiom_session=")][0]
    assert "Secure" in sess and "HttpOnly" in sess and "samesite=lax" in sess.lower()
    csrf = c.cookies.get("axiom_csrf")
    r = c.post(f"{t['origin']}/auth/logout", headers={"X-CSRF-Token": csrf, **{k: v for k, v in SPOOFED.items()
                                                                               if k != "Host"}})
    assert r.status_code == 200
    end = r.json()["end_session_url"]
    assert end.startswith(f"{t['issuer']}/") and parse_qs(urlsplit(end).query)["post_logout_redirect_uri"] == [
        f"{t['origin']}/ui/"]
    assert c.get(f"{t['origin']}/auth/session").status_code == 401           # logged out server-side
    c.close()


# ------------------------------------------------------------------------------------------------- secrets
@pytest.mark.parametrize("problem", ["missing", "empty", "outside", "escaping_link", "too_large"])
def test_secret_file_failures_stop_start_up_without_revealing_contents(tls, dbinfo, db, object_store, tmp_path, problem):
    from axiom.api.app import create_app
    marker = "TOP-SECRET-" + secrets.token_hex(8)
    allowed = tmp_path / "run-secrets"
    allowed.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "secret").write_text(marker)
    target = allowed / "oidc"
    if problem == "empty":
        target.write_text("\n")
    elif problem == "outside":
        target = elsewhere / "secret"
    elif problem == "escaping_link":
        target.symlink_to(elsewhere / "secret")
    elif problem == "too_large":
        target.write_text(marker * 400)
    settings = production_settings(tls, dbinfo, oidc_client_secret_ref=f"secretref:file{target}",
                                   secret_file_dirs=str(allowed))
    with pytest.raises(ConfigurationError) as err:
        create_app(settings, db=db, store=object_store)
    assert marker not in str(err.value) and marker not in repr(err.value.__cause__)
