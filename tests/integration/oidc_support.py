"""Local identity provider (Keycloak 26.4.2, pinned by digest) and a live API server for sign-in and browser tests.

This validates the OpenID Connect protocol path against a real, maintained IdP running locally. It says nothing about
Microsoft Entra ID or any other hosted IdP, which has not been tested.

Secrets: the realm (client secret, user passwords, admin password) is generated at test time in a temporary
directory, passed to the container as a read-only import, and never written into the repository or logs. The client
secret reaches the platform through an environment variable named by a ``secretref:env/`` reference.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field

import httpx
import pytest

KEYCLOAK_IMAGE = ("quay.io/keycloak/keycloak:26.4.2@sha256:"
                  "3617b09bb4b7510a8d8d9b9fc5707399e2d70688dbcc2f8fb013a144829be1b9")
REALM = "axiom"
CLIENT_ID = "axiom-ui"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class User:
    username: str
    password: str
    sub: str
    email: str


@dataclass
class IdP:
    issuer: str
    client_secret_env: str
    api_port: int
    users: dict[str, User] = field(default_factory=dict)
    admin_password: str = ""          # bootstrap admin of this throwaway container (key rotation tests)

    def admin_token(self) -> str:
        base = self.issuer.split("/realms/")[0]
        r = httpx.post(f"{base}/realms/master/protocol/openid-connect/token", timeout=15, data={
            "grant_type": "password", "client_id": "admin-cli", "username": "bootstrap",
            "password": self.admin_password})
        r.raise_for_status()
        return r.json()["access_token"]

    def rotate_signing_key(self, priority: int = 500) -> None:
        """Add a new generated RSA signing key with a higher priority than the existing one, so Keycloak signs new
        tokens with a key ID the platform has not cached."""
        base = self.issuer.split("/realms/")[0]
        h = {"Authorization": f"Bearer {self.admin_token()}"}
        realm = httpx.get(f"{base}/admin/realms/{REALM}", headers=h, timeout=15).json()
        r = httpx.post(f"{base}/admin/realms/{REALM}/components", headers=h, timeout=15, json={
            "name": f"rotated-{priority}", "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm["id"],
            "config": {"priority": [str(priority)], "keySize": ["2048"], "active": ["true"], "enabled": ["true"],
                       "algorithm": ["RS256"]}})
        r.raise_for_status()

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.api_port}/auth/callback"


def _realm(api_port: int, client_secret: str, users: dict[str, User]) -> dict:
    return {
        "realm": REALM, "enabled": True, "sslRequired": "none", "accessTokenLifespan": 300,
        # two users share an email address on purpose: the platform must not merge accounts by email
        "duplicateEmailsAllowed": True, "loginWithEmailAllowed": False,
        "clients": [{
            "clientId": CLIENT_ID, "protocol": "openid-connect", "publicClient": False, "secret": client_secret,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
            "redirectUris": [f"http://127.0.0.1:{api_port}/auth/callback"],
            "attributes": {"pkce.code.challenge.method": "S256",
                           "post.logout.redirect.uris": f"http://127.0.0.1:{api_port}/ui/"}}],
        "users": [{"id": u.sub, "username": u.username, "enabled": True, "email": u.email, "emailVerified": True,
                   "firstName": u.username.title(), "lastName": "Test",
                   "credentials": [{"type": "password", "value": u.password, "temporary": False}]}
                  for u in users.values()],
    }


@pytest.fixture(scope="session")
def keycloak():
    if shutil.which("docker") is None or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        msg = "Docker is not available for the local identity provider"
        (pytest.fail if os.environ.get("AXIOM_REQUIRE_UI") == "1" else pytest.skip)(msg)
    kc_port, api_port = free_port(), free_port()
    users = {name: User(name, secrets.token_urlsafe(18), str(uuid.uuid4()), email)
             for name, email in (("alice", "alice@example.test"), ("bob", "bob@example.test"),
                                 ("mallory", "alice@example.test"))}      # mallory shares alice's email on purpose
    client_secret = secrets.token_urlsafe(32)
    tmp = tempfile.mkdtemp(prefix="axiom-kc-")
    with open(os.path.join(tmp, "realm.json"), "w") as fh:
        json.dump(_realm(api_port, client_secret, users), fh)
    os.chmod(tmp, 0o755)
    os.chmod(os.path.join(tmp, "realm.json"), 0o644)
    name = f"axiom-kc-{uuid.uuid4().hex[:8]}"
    env_name = f"AXIOM_TEST_OIDC_SECRET_{uuid.uuid4().hex[:6].upper()}"
    os.environ[env_name] = client_secret
    admin_password = secrets.token_urlsafe(18)
    subprocess.run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{kc_port}:8080",
                    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap", "-e",
                    f"KC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}",
                    "-v", f"{tmp}:/opt/keycloak/data/import:ro", KEYCLOAK_IMAGE, "start-dev", "--import-realm",
                    f"--hostname=http://127.0.0.1:{kc_port}"], check=True, capture_output=True)
    issuer = f"http://127.0.0.1:{kc_port}/realms/{REALM}"
    try:
        deadline = time.time() + 180
        while time.time() < deadline:
            state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True,
                                   text=True).stdout.strip()
            if state != "true":
                break
            try:
                if httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            logs = subprocess.run(["docker", "logs", "--tail", "40", name], capture_output=True, text=True).stdout
            raise RuntimeError("Keycloak did not start:\n" + re.sub(r"(?i)password\S*", "[redacted]", logs))
        yield IdP(issuer, env_name, api_port, users, admin_password)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
        os.environ.pop(env_name, None)


class LiveServer:
    def __init__(self, app, port: int):
        import uvicorn
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.base = f"http://127.0.0.1:{port}"

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("API server did not start")

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(10)


def provision(dbinfo, world, idp: IdP, *, who: dict[str, tuple[str, list]]) -> dict:
    """Create platform principals for IdP users: who = {username: (tenant 'a'|'b'|None, [(role, scope_attr)])}."""
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    provider = p.ensure_identity_provider(idp.issuer, CLIENT_ID)
    out = {}
    for username, (tenant, roles) in who.items():
        u = idp.users[username]
        import psycopg
        with psycopg.connect(dbinfo.admin_dsn, autocommit=True) as conn:   # test inspection only (superuser)
            row = conn.execute("SELECT principal_id FROM axiom.federated_identities WHERE provider_id = %s AND subject = %s",
                               (provider, u.sub)).fetchone()
            if row:                       # the IdP lives for the session; reuse the principal, re-enable it
                conn.execute("UPDATE axiom.principals SET status = 'active' WHERE id = %s", (row[0],))
        pid = row[0] if row else p.create_principal(f"{username} (sso)", provider_id=provider, subject=u.sub)
        if tenant:
            t = world.a if tenant == "a" else world.b
            p.add_membership(t.id, pid)
            for role, where in roles:
                p.bootstrap_role(t.id, pid, role, getattr(t, where), f"sso test {username}")
        out[username] = pid
    return out


def browserless_login(base: str, idp: IdP, username: str, *, return_to: str = "/ui/",
                      client: httpx.Client | None = None, stop_before_callback: bool = False):
    """Drive the authorization code flow with plain HTTP (the browser tests drive the same pages with Chromium)."""
    c = client or httpx.Client(follow_redirects=False, timeout=15)
    r = c.get(f"{base}/auth/login", params={"return_to": return_to})
    assert r.status_code == 302, r.text
    r = c.get(r.headers["location"])
    assert r.status_code == 200, r.status_code
    action = re.search(r'action="([^"]+)"', r.text).group(1).replace("&amp;", "&")
    u = idp.users[username]
    # Keycloak's login cookies are Secure; a plain HTTP client will not send them to http://127.0.0.1 (a browser
    # treats loopback as trustworthy and does), so forward Keycloak's own cookies explicitly for this request only
    kc = "; ".join(f"{ck.name}={ck.value}" for ck in c.cookies.jar if ck.name.startswith(("AUTH_SESSION", "KC_")))
    r = c.post(action, data={"username": u.username, "password": u.password, "credentialId": ""},
               headers={"Cookie": kc})
    assert r.status_code == 302, re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))[:1500]
    callback = r.headers["location"]
    assert callback.startswith(idp.redirect_uri), callback
    if stop_before_callback:
        return c, callback
    r = c.get(callback)
    return c, r
