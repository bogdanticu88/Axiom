"""The verification worker as an untrusted-input boundary (ADR 0014 amendment 1).

Controlled local services only: TLS servers in the test process with throwaway CAs, and a resolver function that the
test controls instead of DNS. Nothing here contacts another host.
"""
from __future__ import annotations

import logging
import ssl

import pytest

from axiom.ingestion.sync import SyncService
from axiom.jobs import Worker, WorkerConfig
from axiom.provisioning import Provisioner
from axiom.secretrefs import SecretRefResolver
from axiom.verification import checks
from axiom.verification.worker import VerificationCheckHandler

from . import check_target
from .test_cases import advance_to_verification, scenario  # noqa: F401
from .test_verification_worker import TOKEN, clean, job_for, make_due, runs

pytestmark = pytest.mark.db


@pytest.fixture()
def targets(tmp_path):
    made = []

    def make(name, hostnames=()):
        t = check_target.start(tmp_path / name, hostnames)
        t.behaviour = clean
        made.append(t)
        return t
    yield make
    for t in made:
        t.stop()


@pytest.fixture()
def rig(db, world, dbinfo, ctx_for, tmp_path, evidence):
    """Verification identity, an admin able to configure connections, a mounted test credential, and a function that
    builds a worker for a given connection URL, policy, resolver and trust store."""
    prov = Provisioner(dbinfo.admin_cli_dsn)
    prov.create_verification_identity(world.a.id)
    prov.bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "configure check endpoints")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "token").write_text(TOKEN)

    class Rig:
        def connect(self, base_url):
            return SyncService(db, None, None).create_connection(
                ctx_for("admin"), adapter="verification_check", scope_id=world.a.project, display_name="checks",
                base_url=base_url, credential_ref=f"secretref:file{secrets_dir}/token", config={})

        def worker(self, *, policy, resolver, ca=None):
            def factory(conn, secrets, clock, pol):
                ref = conn["credential_ref"]
                verify = ssl.create_default_context(cafile=str(ca)) if ca else True
                return checks.CheckEndpointClient(conn["base_url"], lambda: secrets.resolve(ref), policy=pol,
                                                  resolver=resolver, verify=verify, clock=clock, timeout=3)
            handler = VerificationCheckHandler(
                evidence, secrets=SecretRefResolver(env="test", file_dirs=(str(secrets_dir),)), policy=policy,
                client_factory=factory)
            return Worker(db, [handler], config=WorkerConfig(lease_seconds=30))
    return Rig()


def port_of(t):
    return int(t.base_url.rsplit(":", 1)[1])


def fixed(mapping):
    """A resolver that answers from a dict (name -> list of addresses), or from a callable for changing answers."""
    def resolve(host, port):
        answer = mapping(host) if callable(mapping) else mapping.get(host)
        if answer is None:
            raise checks.CheckUnavailable("check endpoint name did not resolve")
        return answer
    return resolve


def nothing_recorded(admin_conn, cid, verifier_evidence=True):
    assert runs(admin_conn, cid) == []


# --------------------------------------------------------------------------------------- destination policy
def test_an_unapproved_destination_is_never_contacted(world, run, ctx_for, scenario, rig, targets, admin_conn):  # noqa: F811
    t = targets("t", ("check.test",))
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    policy = checks.DestinationPolicy.from_settings("https://other.test:443", "127.0.0.0/8")
    rig.worker(policy=policy, resolver=fixed({"check.test": ["127.0.0.1"]}), ca=t.ca_path).run_once(
        only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "needs_operator" and "not an allowed verification destination" in j["operator_reason"]
    assert t.requests == [] and runs(admin_conn, cid) == []
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "awaiting_verification"


@pytest.mark.parametrize("addresses,networks,why", [
    (["127.0.0.1"], "", "never contacted by default"),                       # loopback, no explicit allowance
    (["169.254.169.254"], "", "never contacted by default"),                 # cloud metadata
    (["127.0.0.1", "10.9.9.9"], "127.0.0.0/8", "outside the allowed networks"),   # one bad answer is enough
])
def test_resolved_addresses_must_be_allowed(world, run, ctx_for, scenario, rig, targets, admin_conn,  # noqa: F811
                                            addresses, networks, why):
    t = targets("t", ("check.test",))
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, networks),
               resolver=fixed({"check.test": addresses}), ca=t.ca_path).run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "needs_operator" and why in j["operator_reason"]
    assert t.requests == [] and runs(admin_conn, cid) == []


def test_the_connection_is_pinned_to_the_checked_address_and_verified_for_the_name(  # noqa: F811
        world, run, ctx_for, scenario, rig, targets, admin_conn):
    t = targets("t", ("check.test",))
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
               resolver=fixed({"check.test": ["127.0.0.1"]}), ca=t.ca_path).run_once(only_tenants={world.a.id})
    [req] = t.requests
    assert req["headers"]["Host"] == f"check.test:{port_of(t)}"
    [r] = runs(admin_conn, cid)
    obs = admin_conn.execute("SELECT * FROM axiom.verification_observations WHERE verification_run_id = %s",
                             (r["id"],)).fetchone()
    assert (r["outcome"], str(obs["connected_address"]), obs["response_redacted"]) == ("passed", "127.0.0.1", False)


def test_an_address_change_between_attempts_is_checked_again(world, run, ctx_for, scenario, rig, targets,  # noqa: F811
                                                             admin_conn):
    """The first attempt resolves to the allowed address and gets a 503; by the retry the name points at the cloud
    metadata address. The retry is refused before connecting."""
    t = targets("t", ("check.test",))
    t.behaviour = lambda req: (503, None)
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    answers = iter([["127.0.0.1"], ["169.254.169.254"]])
    w = rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
                   resolver=fixed(lambda host: next(answers)), ca=t.ca_path)
    w.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "queued" and len(t.requests) == 1
    make_due(admin_conn, j["id"])
    w.run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "needs_operator" and "169.254.169.254" in j["operator_reason"]
    assert len(t.requests) == 1 and runs(admin_conn, cid) == []


@pytest.mark.parametrize("problem", ["wrong_name", "untrusted_ca"])
def test_tls_failures_park_the_job_without_sending_the_request(world, run, ctx_for, scenario, rig, targets,  # noqa: F811
                                                              admin_conn, problem):
    t = targets("t", ("check.test",))
    host = "other.test" if problem == "wrong_name" else "check.test"      # certificate names check.test only
    url = f"https://{host}:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
               resolver=fixed({host: ["127.0.0.1"]}),
               ca=t.ca_path if problem == "wrong_name" else None).run_once(only_tenants={world.a.id})
    j = job_for(admin_conn, cid)
    assert j["state"] == "needs_operator" and "TLS certificate was not trusted" in j["operator_reason"]
    assert t.requests == [] and runs(admin_conn, cid) == []
    assert TOKEN not in (j["operator_reason"] or "")


# --------------------------------------------------------------------------------------- responses
def test_a_redirect_is_not_followed_and_its_target_receives_nothing(world, run, ctx_for, scenario, rig, targets,  # noqa: F811
                                                                     admin_conn):
    t = targets("t", ("check.test",))
    elsewhere = targets("elsewhere", ("evil.test",))
    t.behaviour = lambda req: (307, None, {"Location": f"https://evil.test:{port_of(elsewhere)}/v1/checks"})
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
               resolver=fixed({"check.test": ["127.0.0.1"], "evil.test": ["127.0.0.1"]}), ca=t.ca_path).run_once(
        only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"]) == ("inconclusive", "target_refused")
    assert len(t.requests) == 1 and elsewhere.requests == []


@pytest.mark.parametrize("answer,rule", [
    (lambda req: (200, b"{" + b" " * (checks.MAX_RESPONSE_BYTES + 10) + b"}"), "malformed_response"),
    (lambda req: (200, {"schema": checks.SCHEMA, "status": "ok", "coverage": "complete", "results": [],
                        "request_id": req["request_id"]}), "unbound_response"),       # generic success
    (lambda req: clean(req, nonce="replayed"), "unbound_response"),
    (lambda req: clean(req, asset_id="some-other-asset"), "unbound_response"),
])
def test_oversized_generic_or_unbound_responses_do_not_verify(world, run, ctx_for, scenario, rig, targets,  # noqa: F811
                                                              admin_conn, answer, rule):
    t = targets("t", ("check.test",))
    t.behaviour = answer
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
               resolver=fixed({"check.test": ["127.0.0.1"]}), ca=t.ca_path).run_once(only_tenants={world.a.id})
    [r] = runs(admin_conn, cid)
    assert (r["outcome"], r["rule"]) == ("inconclusive", rule)


def test_an_echoed_credential_is_redacted_and_never_stored_or_logged(world, run, ctx_for, scenario, rig, targets,  # noqa: F811
                                                                    admin_conn, evidence, caplog):
    t = targets("t", ("check.test",))

    def echo(req):
        status, doc = clean(req)
        return status, {**doc, "debug": {"received_authorization": t.requests[-1]["headers"]["Authorization"]}}
    t.behaviour = echo
    url = f"https://check.test:{port_of(t)}"
    rig.connect(url)
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    caplog.set_level(logging.DEBUG)
    rig.worker(policy=checks.DestinationPolicy.from_settings(url, "127.0.0.0/8"),
               resolver=fixed({"check.test": ["127.0.0.1"]}), ca=t.ca_path).run_once(only_tenants={world.a.id})
    assert t.requests[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"     # it was sent, to this endpoint only
    [r] = runs(admin_conn, cid)
    assert r["outcome"] == "passed"
    obs = admin_conn.execute("SELECT * FROM axiom.verification_observations WHERE verification_run_id = %s",
                             (r["id"],)).fetchone()
    assert obs["response_redacted"] is True
    verifier = admin_conn.execute("SELECT verification_principal_id AS p FROM axiom.tenants WHERE id = %s",
                                  (world.a.id,)).fetchone()["p"]
    from axiom.db import TenantContext
    stored = b"".join(evidence.open_for_read(TenantContext(world.a.id, verifier, "workload", "t"),
                                             r["evidence_object_id"], purpose="test").chunks)
    assert TOKEN.encode() not in stored and checks.REDACTED in stored
    for table in ("verification_observations", "verification_runs", "decisions", "audit_events", "jobs",
                  "job_events", "evidence_objects", "case_events"):
        dump = admin_conn.execute(f"SELECT string_agg(t::text, ' ') AS s FROM axiom.{table} t").fetchone()["s"] or ""
        assert TOKEN not in dump, table
    assert TOKEN not in caplog.text
