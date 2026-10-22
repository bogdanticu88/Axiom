"""Action and approval protocol (Specification S 9, Plan S 7, Design S 7; ADR 0010).

External system: the local Jira-style fake (tests/integration/jira_fake.py). Support level of the Jira-style
integration is **fixture-tested**; nothing here exercises a real Jira site. Capability variants of the fake
(idempotency keys, unique external ids, fencing) model hypothetical providers, not Jira.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.actions.jobs import ActionExecuteHandler
from axiom.domains.actions.service import ActionService
from axiom.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axiom.ingestion.sync import SyncService
from axiom.integrations.jira_style import JIRA_CLOUD, JiraStyleClient, JiraStyleTicketAdapter, TrackerCapabilities
from axiom.jobs import EffectGate, JobOperations, Worker, WorkerConfig, enqueue

from .jira_fake import JiraStyleFake

pytestmark = pytest.mark.db
FAST = WorkerConfig(lease_seconds=1.0, step_timeout_seconds=2.0, per_tenant_running_limit=20, batch_per_tenant=20,
                    max_backoff_seconds=0.01)
IDEMPOTENT = TrackerCapabilities(dedupe="idempotency_key")
UNIQUE = TrackerCapabilities(dedupe="unique_external_id")
FENCED = TrackerCapabilities(provider_fencing=True)
PAYLOAD = {"project_key": "SEC", "summary": "Upgrade openssl in payments-api", "description": "CVE-2099-0001",
           "labels": ["axiom"]}


def soon(days=7):
    return datetime.now(timezone.utc) + timedelta(days=days)


class Env:
    def __init__(self, db, world, ctx_for, dbinfo, run):
        from axiom.provisioning import Provisioner
        self.db, self.world, self.ctx_for, self.run = db, world, ctx_for, run
        prov = Provisioner(dbinfo.admin_cli_dsn)
        prov.bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "configure tracker; reconcile")
        self.case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="openssl"))
        self.connection = SyncService(db, None, None).create_connection(
            ctx_for("admin"), adapter="jira_style", scope_id=world.a.project, display_name="tracker",
            base_url="https://tracker.test.invalid", credential_ref="secretref:test/tracker", config={})
        self.fake = JiraStyleFake()
        self.caps = JIRA_CLOUD

    def adapter(self, *_):
        client = JiraStyleClient("https://tracker.test.invalid", lambda: ("bot@example.invalid", "token"),
                                 transport=self.fake.transport())
        return JiraStyleTicketAdapter(client, self.caps)

    def worker(self, worker_id="w", config=FAST):
        return Worker(self.db, [ActionExecuteHandler(self.adapter)], worker_id=worker_id, config=config)

    def svc(self, who, fn):
        ctx = self.ctx_for(who)
        with self.db.tenant_tx(ctx) as conn:
            return fn(ActionService(conn, ctx, Authorizer(conn, ctx)))

    def propose(self, payload=None, who="analyst"):
        return self.svc(who, lambda s: s.propose(case_id=self.case["id"], effect="ticket.create",
                                                 connection_id=self.connection["id"], payload=payload or PAYLOAD,
                                                 verification_criteria="ticket exists and links the case",
                                                 expires_at=soon()))

    def approve(self, proposal, version=1, max_uses=1, who="approver", **kw):
        return self.svc(who, lambda s: s.decide(proposal["id"], version, decision="approved", rationale="ok",
                                                max_uses=max_uses, **kw))

    def execute(self, proposal, approval, version=1, who="analyst"):
        return self.svc(who, lambda s: s.request_execution(proposal["id"], version, approval["id"]))

    def execution(self, execution_id):
        return self.svc("analyst", lambda s: s.get_execution(execution_id))

    def job(self, job_id):
        with self.db.tenant_tx(self.ctx_for("system")) as conn:
            return conn.execute("SELECT * FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()

    def drive(self, admin_conn, job_id, passes=6, worker=None):
        w = worker or self.worker()
        for _ in range(passes):
            if self.job(job_id)["state"] not in ("queued", "waiting", "running"):
                break
            admin_conn.execute("UPDATE axiom.jobs SET due_at = clock_timestamp(), record_version = record_version + 1 "
                               "WHERE id = %s AND state IN ('queued', 'waiting')", (job_id,))
            w.run_once(only_tenants={self.world.a.id})
        return self.job(job_id)


@pytest.fixture()
def env(db, world, ctx_for, dbinfo, run):
    return Env(db, world, ctx_for, dbinfo, run)


# --------------------------------------------------------------------------------------------- proposals
def test_digest_is_computed_by_the_database_and_versions_are_immutable(env, admin_conn):
    p = env.propose()
    v = p["version"]
    again = admin_conn.execute("SELECT axiom.proposal_binding_digest(v) AS d FROM axiom.action_proposal_versions v "
                               "WHERE id = %s", (v["id"],)).fetchone()["d"]
    assert v["payload_digest"] == again and len(again) == 64
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
            conn.execute("UPDATE axiom.action_proposal_versions SET canonical_payload = '{}' WHERE id = %s", (v["id"],))
    # a different payload yields a different digest
    other = env.propose({**PAYLOAD, "summary": "Something else"})
    assert other["version"]["payload_digest"] != v["payload_digest"]


def test_payload_validation_and_disabled_effect_classes(env):
    with pytest.raises(ValidationFailed):
        env.propose({**PAYLOAD, "labels": ["axiom-op-forged"]})
    with pytest.raises(ValidationFailed):
        env.propose({**PAYLOAD, "assignee": "someone"})
    with pytest.raises(ValidationFailed) as err:
        env.svc("analyst", lambda s: s.propose(case_id=env.case["id"], effect="production.change",
                                               connection_id=env.connection["id"], payload=PAYLOAD,
                                               verification_criteria="x", expires_at=soon()))
    assert err.value.code == "effect_class_disabled"
    with pytest.raises(PermissionDenied):
        env.propose(who="viewer")


def test_proposer_cannot_approve_in_service_or_database(env, dbinfo, world):
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["analyst2"], "approver", world.a.project,
                                                     "analyst who also approves")
    p = env.propose(who="analyst2")
    with pytest.raises(Forbidden) as err:
        env.approve(p, who="analyst2")
    assert err.value.code == "separation_of_duties"
    # bypassing the service: the database refuses too
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with env.db.tenant_tx(env.ctx_for("analyst2")) as conn:
            conn.execute(
                """INSERT INTO axiom.approvals(tenant_id, id, proposal_id, proposal_version_id, payload_digest, decision,
                       approver_principal_id, authorised_scope_id, authority_snapshot, rationale, valid_until, max_uses,
                       status) VALUES (%s, %s, %s, %s, %s, 'approved', %s, %s, '{}', 'self', %s, 1, 'active')""",
                (world.a.id, uuid.uuid4(), p["id"], p["version"]["id"], p["version"]["payload_digest"],
                 world["analyst2"], world.a.project, soon(1)))


def test_approval_cannot_point_at_a_different_digest(env, world):
    p = env.propose()
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with env.db.tenant_tx(env.ctx_for("approver")) as conn:
            conn.execute(
                """INSERT INTO axiom.approvals(tenant_id, id, proposal_id, proposal_version_id, payload_digest, decision,
                       approver_principal_id, authorised_scope_id, authority_snapshot, rationale, valid_until, max_uses,
                       status) VALUES (%s, %s, %s, %s, %s, 'approved', %s, %s, '{}', 'x', %s, 1, 'active')""",
                (world.a.id, uuid.uuid4(), p["id"], p["version"]["id"], "0" * 64, world["approver"],
                 world.a.project, soon(1)))


def test_revision_after_approval_requires_new_approval(env, admin_conn):
    """A08: changing the arguments after approval needs a new approval."""
    p = env.propose()
    a1 = env.approve(p)
    env.svc("analyst", lambda s: s.revise(p["id"], 1, payload={**PAYLOAD, "summary": "Changed"},
                                          verification_criteria="x", expires_at=soon()))
    with pytest.raises(Conflict) as err:
        env.execute(p, a1, version=2)
    assert err.value.code == "approval_mismatch"
    with pytest.raises(Conflict) as err:
        env.execute(p, a1, version=1)
    assert err.value.code == "stale_version"
    a2 = env.approve(p, version=2)
    e = env.execute(p, a2, version=2)
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert [i["summary"] for i in env.fake.issues] == ["Changed"]


def test_approval_limits(env):
    p = env.propose()
    with pytest.raises(ValidationFailed):
        env.approve(p, max_uses=4)                           # ticket.create allows at most 3
    with pytest.raises(ValidationFailed):
        env.approve(p, valid_until=soon(60))                  # beyond the proposal's expiry
    with pytest.raises(NotFound):                             # viewers cannot even see proposals
        env.approve(p, who="viewer")
    with pytest.raises(PermissionDenied):                     # analysts can see but not approve
        env.approve(p, who="analyst2")


# ------------------------------------------------------------------------------------------ reservations
def test_concurrent_reservations_never_exceed_max_uses(env):
    p = env.propose()
    a = env.approve(p, max_uses=2)
    results, barrier = [], threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            results.append(("ok", env.execute(p, a)["id"]))
        except Conflict as exc:
            results.append((exc.code, None))
    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    oks = [r for r in results if r[0] == "ok"]
    assert len(oks) == 2 and len(results) == 8
    assert {r[0] for r in results if r[0] != "ok"} == {"approval_exhausted"}
    with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
        row = conn.execute("SELECT uses_reserved FROM axiom.approvals WHERE id = %s", (a["id"],)).fetchone()
        uses = sorted(r["use_number"] for r in conn.execute(
            "SELECT use_number FROM axiom.approval_reservations WHERE approval_id = %s", (a["id"],)))
    assert row["uses_reserved"] == 2 and uses == [1, 2]


def test_reservation_accounting_is_guarded_in_the_database(env):
    p = env.propose()
    a = env.approve(p, max_uses=2)
    with pytest.raises(psycopg.errors.CheckViolation):
        with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
            conn.execute("UPDATE axiom.approvals SET uses_reserved = uses_reserved + 2, "
                         "record_version = record_version + 1 WHERE id = %s", (a["id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):          # max_uses is not updatable at all
        with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
            conn.execute("UPDATE axiom.approvals SET max_uses = 5, record_version = record_version + 1 "
                         "WHERE id = %s", (a["id"],))


# -------------------------------------------------------------------------------------------- executions
def test_execution_creates_one_verified_ticket_and_does_not_touch_the_case(env, admin_conn):
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    got = env.execution(e["id"])
    assert got["state"] == "succeeded" and got["external_ref"] == "SEC-1"
    [ref] = got["external_references"]
    assert ref["verified"] is True and ref["how"] == "created"
    assert env.fake.keys() == ["SEC-1"]
    assert env.fake.issues[0]["labels"][0] == f"axiom-op-{e['external_operation_id']}"
    with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
        res = conn.execute("SELECT status FROM axiom.approval_reservations WHERE execution_id = %s", (e["id"],)).fetchone()
        case = conn.execute("SELECT workflow, record_version FROM axiom.finding_cases WHERE id = %s",
                            (env.case["id"],)).fetchone()
    assert res["status"] == "consumed"
    assert case["workflow"] == "received" and case["record_version"] == 0      # ACT-09: tickets do not move cases
    with pytest.raises(Conflict) as err:                                         # single use spent
        env.execute(p, a)
    assert err.value.code == "approval_exhausted"


def test_revocation_before_execution_denies_and_returns_the_unused_use(env, admin_conn):
    """A07: revoke approval before execution -> deny and record why."""
    p = env.propose()
    a = env.approve(p, max_uses=2)
    e = env.execute(p, a)
    env.svc("approver", lambda s: s.revoke_approval(a["id"], "scope changed"))
    assert env.drive(admin_conn, e["job_id"])["state"] == "failed"
    got = env.execution(e["id"])
    assert got["state"] == "failed" and "approval is revoked" in got["outcome_detail"]["error"]
    assert env.fake.create_requests == 0
    with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
        res = conn.execute("SELECT status, release_reason FROM axiom.approval_reservations WHERE execution_id = %s",
                           (e["id"],)).fetchone()
    assert res["status"] == "released"


def test_approver_losing_membership_before_execution_denies(env, admin_conn, world):
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    env.run(env.ctx_for("admin"), lambda s: s.tenancy.suspend_membership(principal_id=world["approver"],
                                                                           reason="left the team"))
    assert env.drive(admin_conn, e["job_id"])["state"] == "failed"
    assert "approver no longer holds action.approve" in env.execution(e["id"])["outcome_detail"]["error"]
    assert env.fake.create_requests == 0


def test_material_change_after_approval_denies(env, admin_conn):
    """ACT-10. No prioritisation command exists yet (Phase C), so the priority change is injected directly as a
    superuser with triggers disabled; this is fault injection, not a supported path."""
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    admin_conn.execute("SET session_replication_role = replica")
    admin_conn.execute("UPDATE axiom.finding_cases SET priority = 'urgent' WHERE id = %s", (env.case["id"],))
    admin_conn.execute("SET session_replication_role = origin")
    assert env.drive(admin_conn, e["job_id"])["state"] == "failed"
    assert "material change" in env.execution(e["id"])["outcome_detail"]["error"]
    assert env.fake.create_requests == 0


def test_cancel_before_any_attempt_returns_the_use(env):
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    env.svc("analyst", lambda s: s.cancel_execution(e["id"], "duplicate request"))
    got = env.execution(e["id"])
    assert got["state"] == "cancelled"
    assert env.execute(p, a)["state"] == "prepared"           # the single use was returned, so this succeeds


def test_a_use_is_never_returned_once_the_effect_may_have_been_attempted(env, admin_conn):
    env.fake.lose_ack = 1
    env.fake.search_lag = 3600
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    env.worker().run_once(only_tenants={env.world.a.id})       # attempt; ack lost
    with pytest.raises(psycopg.errors.CheckViolation):
        with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
            conn.execute("UPDATE axiom.approval_reservations SET status = 'released', release_reason = 'timeout', "
                         "record_version = record_version + 1 WHERE execution_id = %s", (e["id"],))


# ------------------------------------------------------------------------------ lost acknowledgements
def test_lost_ack_with_lagging_search_parks_instead_of_creating_again(env, admin_conn):
    """Lookup before create alone does not prevent duplicates: the search index has not caught up, so the
    lookup misses. The gate must not create again; it parks for reconciliation."""
    env.fake.lose_ack, env.fake.search_lag = 1, 3600
    p = env.propose()
    e = env.execute(p, env.approve(p))
    job = env.drive(admin_conn, e["job_id"])
    assert job["state"] == "needs_operator"
    assert env.fake.create_requests == 1 and len(env.fake.issues) == 1
    assert env.execution(e["id"])["state"] == "reconciling"
    # the operator finds SEC-1 carrying the operation label and adopts it; the approval is not touched
    with pytest.raises(PermissionDenied):
        env.svc("analyst", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="x", external_ref="SEC-1"))
    env.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", external_ref="SEC-1",
                                           rationale="found SEC-1 with label axiom-op-... in the tracker"))
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    got = env.execution(e["id"])
    assert got["state"] == "succeeded" and got["external_references"][0]["how"] == "adopted_by_operator"
    assert env.fake.create_requests == 1 and len(env.fake.issues) == 1


def test_lost_ack_adopted_when_the_index_has_caught_up(env, admin_conn):
    env.fake.lose_ack = 1
    p = env.propose()
    e = env.execute(p, env.approve(p))
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert env.execution(e["id"])["external_references"][0]["how"] == "adopted_by_lookup"
    assert len(env.fake.issues) == 1


def test_lost_ack_with_provider_idempotency_retries_safely(env, admin_conn):
    env.fake = JiraStyleFake(search_lag=3600, idempotency=True)
    env.fake.lose_ack = 1
    env.caps = IDEMPOTENT
    p = env.propose()
    e = env.execute(p, env.approve(p))
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert env.fake.create_requests == 2 and len(env.fake.issues) == 1


def test_misdeclared_capability_is_the_failure_mode(env, admin_conn):
    """Control: claiming idempotency for a provider that does not honour it re-creates. Capability declarations
    must be true; the jira_style connection never declares deduplication."""
    env.fake.lose_ack, env.fake.search_lag = 1, 3600
    env.caps = IDEMPOTENT                        # wrong: the fake was not built with idempotency=True
    p = env.propose()
    e = env.execute(p, env.approve(p))
    env.drive(admin_conn, e["job_id"])
    assert len(env.fake.issues) == 2


def test_unprocessed_and_connect_failures_retry_without_duplicates(env, admin_conn):
    env.fake.connect_error = 1                  # never sent: definitely not applied, safe to retry
    p = env.propose()
    e = env.execute(p, env.approve(p))
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert len(env.fake.issues) == 1
    env.fake.fail_unprocessed = 1               # 503: we cannot know it was unprocessed -> unknown -> lookup
    p2 = env.propose({**PAYLOAD, "summary": "second"})
    e2 = env.execute(p2, env.approve(p2))
    assert env.drive(admin_conn, e2["job_id"])["state"] == "needs_operator"
    assert len(env.fake.issues) == 1           # nothing created; operator confirms not applied, then it runs
    env.svc("admin", lambda s: s.reconcile(e2["id"], resolution="not_applied",
                                           rationale="no SEC issue with this operation label exists"))
    assert env.drive(admin_conn, e2["job_id"])["state"] == "succeeded"
    assert len(env.fake.issues) == 2


# ---------------------------------------------------------------------- stale worker at the effect boundary
@pytest.mark.parametrize("caps,fake_kw,expect_second_create", [
    (JIRA_CLOUD, {}, False), (IDEMPOTENT, {"idempotency": True}, True),
    (UNIQUE, {"unique_label": True}, True), (FENCED, {"fencing": True}, True)],
    ids=["jira-style", "provider-idempotency", "provider-unique-id", "provider-fencing"])
def test_stale_worker_already_past_the_boundary(env, admin_conn, caps, fake_kw, expect_second_create):
    """Worker A has marked the intent executing and its request is in flight (held inside the provider). Its
    lease is then lost and worker B takes over. Discarding A's result cannot stop A's request."""
    env.fake, env.caps = JiraStyleFake(search_lag=3600, **fake_kw), caps
    env.fake.hold_armed = True
    p = env.propose()
    e = env.execute(p, env.approve(p))
    a_worker = env.worker("A", WorkerConfig(lease_seconds=0.5, step_timeout_seconds=30, max_backoff_seconds=0.01))
    [(job, token)] = a_worker.claim(env.ctx_for("system"))
    t = threading.Thread(target=a_worker.execute, args=(env.ctx_for("system"), job, token))
    t.start()
    assert env.fake.at_boundary.wait(10)
    admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second',
                                 step_deadline_at = clock_timestamp() - interval '1 second',
                                 record_version = record_version + 1 WHERE id = %s""", (job["id"],))
    env.worker("B").run_once(only_tenants={env.world.a.id})
    after_b = env.job(job["id"])["state"]
    env.fake.release.set()
    t.join(30)
    assert len(env.fake.issues) == 1, env.fake.keys()
    assert env.fake.create_requests == (2 if expect_second_create else 1)
    if not expect_second_create:
        assert after_b == "needs_operator"     # B refused to create; A's request landed meanwhile
    ev = [r["event"] for r in admin_conn.execute(
        "SELECT event FROM axiom.job_events WHERE job_id = %s ORDER BY created_at, id", (job["id"],))]
    assert "stale_result_discarded" in ev or env.job(job["id"])["state"] in ("needs_operator", "succeeded")
    # the execution record reflects the external fact once known
    got = env.execution(e["id"])
    assert got["state"] in ("succeeded", "reconciling")


def test_two_jobs_racing_on_one_operation_key_send_one_first_attempt(env, db, world, ctx_for):
    """Double dispatch (two different jobs, same operation key): both pass lookup, then the intent row is
    re-read under lock when marking it executing, so only one sends a request; the other parks."""
    barrier = threading.Barrier(2)
    adapter = env.adapter()
    real_find = adapter.find

    def find(key):
        hit = real_find(key)
        barrier.wait(10)
        return hit
    adapter.find = find
    key = "a" * 64

    class Handler:
        kind = "test.race"
        versions = frozenset({1})
        current_version = 1

        def step(self, jc):
            return EffectGate(jc).run(adapter, {"project_key": "SEC", "summary": "race", "description": "",
                                                "labels": []}, lambda c: None, key=key).step
    sys_ctx = ctx_for("system")
    with db.tenant_tx(sys_ctx) as conn:
        j1 = enqueue(conn, sys_ctx, kind="test.race", version=1, payload={"n": 1})
        j2 = enqueue(conn, sys_ctx, kind="test.race", version=1, payload={"n": 2})
    w1, w2 = (Worker(db, [Handler()], worker_id=n, config=FAST) for n in ("r1", "r2"))
    claims = [w1.claim(sys_ctx, limit=1), w2.claim(sys_ctx, limit=1)]
    threads = [threading.Thread(target=w.execute, args=(sys_ctx, *c[0])) for w, c in zip((w1, w2), claims)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    states = sorted(env.job(j)["state"] for j in (j1["id"], j2["id"]))
    assert states == ["needs_operator", "succeeded"]
    assert env.fake.create_requests == 1 and len(env.fake.issues) == 1


def test_concurrent_workers_many_executions_no_duplicates(env, admin_conn):
    executions = []
    for n in range(4):
        p = env.propose({**PAYLOAD, "summary": f"batch {n}"})
        a = env.approve(p, max_uses=3)
        executions += [env.execute(p, a) for _ in range(3)]
    workers = [env.worker(f"c{n}") for n in range(4)]

    def loop(w):
        for _ in range(10):
            w.run_once(only_tenants={env.world.a.id})
    threads = [threading.Thread(target=loop, args=(w,)) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    states = [env.execution(e["id"])["state"] for e in executions]
    assert states == ["succeeded"] * 12
    labels = [i["labels"][0] for i in env.fake.issues]
    assert len(labels) == 12 == len(set(labels)) == env.fake.create_requests
    with env.db.tenant_tx(env.ctx_for("system")) as conn:
        claimed_twice = conn.execute(
            """SELECT count(*) AS n FROM (SELECT job_id, lease_token FROM axiom.job_events WHERE event = 'claimed'
                 AND job_id = ANY(%s) GROUP BY job_id, lease_token HAVING count(*) > 1) x""",
            ([e["job_id"] for e in executions],)).fetchone()["n"]
    assert claimed_twice == 0


# ------------------------------------------------------------------------------------------ idempotency keys
def test_idempotency_key_replays_and_rejects_reuse_with_different_arguments(env):
    from axiom import idempotency
    p = env.propose()
    a = env.approve(p, max_uses=3)
    ctx = env.ctx_for("analyst")

    def call(key, approval_id):
        digest = idempotency.request_digest("execute", {"proposal": str(p["id"]), "version": 1},
                                            {"approval_id": str(approval_id)})
        with env.db.tenant_tx(ctx) as conn:
            svc = ActionService(conn, ctx, Authorizer(conn, ctx))
            return idempotency.run(conn, ctx, endpoint="execute", key=key, digest=digest, status=202,
                                   fn=lambda: {"id": str(svc.request_execution(p["id"], 1, approval_id)["id"])})
    first = call("key-00000001", a["id"])
    again = call("key-00000001", a["id"])
    assert first[1] == again[1] and again[2] is True and first[2] is False
    with pytest.raises(idempotency.IdempotencyKeyReused):
        call("key-00000001", uuid.uuid4())
    # concurrent requests with one key: one execution
    barrier, out = threading.Barrier(4), []

    def racer():
        barrier.wait()
        out.append(call("key-00000002", a["id"])[1]["id"])
    threads = [threading.Thread(target=racer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(set(out)) == 1 and len(out) == 4
    with env.db.tenant_tx(ctx) as conn:
        n = conn.execute("SELECT uses_reserved FROM axiom.approvals WHERE id = %s", (a["id"],)).fetchone()
    assert n["uses_reserved"] == 2


def test_idempotency_keys_are_scoped_per_principal(env, world):
    from axiom import idempotency
    digest = idempotency.request_digest("noop", {}, {})
    for who in ("analyst", "analyst2"):
        ctx = env.ctx_for(who)
        with env.db.tenant_tx(ctx) as conn:
            _, body, replayed = idempotency.run(conn, ctx, endpoint="noop", key="shared-key-1", digest=digest,
                                                fn=lambda w=who: {"who": w})
        assert replayed is False and body == {"who": who}


def test_operator_actions_are_audited_and_need_their_permission(env, admin_conn):
    env.fake.lose_ack, env.fake.search_lag = 1, 3600
    p = env.propose()
    e = env.execute(p, env.approve(p))
    env.drive(admin_conn, e["job_id"])
    env.svc("admin", lambda s: s.reconcile(e["id"], resolution="abandon", rationale="linked by hand"))
    got = env.execution(e["id"])
    assert got["state"] == "failed"
    with env.db.tenant_tx(env.ctx_for("auditor")) as conn:
        actions = [r["action"] for r in conn.execute(
            "SELECT action FROM axiom.audit_events WHERE resource_id = %s ORDER BY occurred_at", (str(e["job_id"]),))]
        res = conn.execute("SELECT status FROM axiom.approval_reservations WHERE execution_id = %s",
                           (e["id"],)).fetchone()
    assert "job.effect_abandon" in actions
    assert res["status"] == "consumed"           # the effect may exist: the use is not returned
    with pytest.raises(PermissionDenied):
        with env.db.tenant_tx(env.ctx_for("approver")) as conn:
            JobOperations(conn, env.ctx_for("approver"), Authorizer(conn, env.ctx_for("approver"))).list_attention()


# ------------------------------------------------------------------------------- per-class permissions (ACT-08)
def test_weaker_class_permissions_never_authorise_a_stronger_effect(env, admin_conn, dbinfo, world, monkeypatch):
    """production.change is disabled in the product; it is enabled here, in-process only, against the fake tracker,
    to show that ticket permissions cannot propose, approve or execute it."""
    from dataclasses import replace

    from axiom.domains.actions import model
    from axiom.provisioning import Provisioner
    monkeypatch.setitem(model.REGISTRY, "production.change",
                        replace(model.REGISTRY["production.change"], enabled=True, adapters=("jira_style",), max_uses_limit=1))
    prov = Provisioner(dbinfo.admin_cli_dsn)

    def propose_change(who):
        return env.svc(who, lambda s: s.propose(case_id=env.case["id"], effect="production.change",
                                                connection_id=env.connection["id"], payload=PAYLOAD,
                                                verification_criteria="change applied", expires_at=soon()))
    with pytest.raises(PermissionDenied):                     # analyst: ticket permissions only
        propose_change("analyst")
    prov.bootstrap_role(world.a.id, world["analyst2"], "production_change_requester", world.a.project, "test")
    p = propose_change("analyst2")
    with pytest.raises(PermissionDenied):                     # ticket approver cannot approve a production change
        env.approve(p, who="approver")
    prov.bootstrap_role(world.a.id, world["consultant"], "production_change_approver", world.a.project, "test")
    a = env.approve(p, who="consultant")
    with pytest.raises(PermissionDenied):                     # ticket executor cannot request it either
        env.execute(p, a, who="analyst")
    e = env.execute(p, a, who="analyst2")
    # the stronger approver cannot approve tickets: no hierarchy in either direction
    t = env.propose()
    with pytest.raises(PermissionDenied):
        env.approve(t, who="consultant")
    # revoking the class-specific role before execution denies at the effect boundary
    admin_conn.execute("UPDATE axiom.role_bindings SET revoked_at = now() WHERE principal_id = %s AND role_id = "
                       "'production_change_approver'", (world["consultant"],))
    assert env.drive(admin_conn, e["job_id"])["state"] == "failed"
    assert "action.approve:production_change" in env.execution(e["id"])["outcome_detail"]["error"]
    assert env.fake.create_requests == 0


def test_generic_action_permissions_no_longer_grant_anything(env, admin_conn):
    rows = admin_conn.execute("SELECT role_id, permission FROM axiom.role_permissions WHERE permission IN "
                              "('action.propose', 'action.approve', 'action.execute')").fetchall()
    assert rows == []
