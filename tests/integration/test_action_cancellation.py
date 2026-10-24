"""Cancelling an action execution (ADR 0010 amendment 2026-10-25).

Cancelling stops scheduling; it does not establish that an external action was cancelled. These tests check the
execution record, the job, the effect intent and the approval accounting together, for cancellations that race the
effect gate: before a dispatch is authorized, after it is authorized but before the outcome is known, and around a
recorded success; and for the operator's reconciliation afterwards and a stale worker after a takeover.

External system: the local Jira-style fake (fixture-tested only). Coordination is by events inside the adapter, the
fake provider and the gate, and by moving lease timestamps with the database clock; no sleeps.
"""
from __future__ import annotations

import threading

import pytest

from axiom.access import Authorizer
from axiom.domains.actions.jobs import ActionExecuteHandler
from axiom.errors import Conflict
from axiom.jobs import JobOperations, Worker

from .jira_fake import JiraStyleFake
from .test_actions import FENCED, LONG, _expire_lease, _reservation, env, hooked_gate  # noqa: F401

pytestmark = pytest.mark.db


# ------------------------------------------------------------------------------------------------- helpers
def facts(env, admin_conn, e, a) -> dict:
    """Execution, job, effect evidence and approval accounting, read together."""
    got = env.execution(e["id"])
    approval = admin_conn.execute("SELECT uses_reserved, uses_released FROM axiom.approvals WHERE id = %s",
                                  (a["id"],)).fetchone()
    return {"job": env.job(e["job_id"])["state"], "execution": got["state"], "external_ref": got["external_ref"],
            "intent": got["intent"]["state"] if got["intent"] else None,
            "reservation": _reservation(admin_conn, e["id"]),
            "uses": (approval["uses_reserved"], approval["uses_released"]),
            "creates": env.fake.create_requests, "tickets": len(env.fake.issues)}


def second_execution(env, p, a) -> str:
    """Can the same approval authorize a fresh execution now?"""
    try:
        env.execute(p, a)
        return "allowed"
    except Conflict as exc:
        return f"refused:{exc.code}"


def events(admin_conn, job_id) -> list[dict]:
    return admin_conn.execute("SELECT event, lease_token, worker, detail FROM axiom.job_events WHERE job_id = %s "
                              "ORDER BY created_at, id", (job_id,)).fetchall()


def paused(env, method: str, reached: threading.Event, proceed: threading.Event):
    """An adapter factory whose ``find`` (before the gate authorizes a dispatch) or ``create`` (after it has, before
    the request is sent) waits for the test."""
    def factory(*args):
        adapter = env.adapter()
        real = getattr(adapter, method)

        def wrapper(*a, **kw):
            reached.set()
            proceed.wait(15)
            return real(*a, **kw)
        setattr(adapter, method, wrapper)
        return adapter
    return factory


@pytest.fixture()
def threads():
    """Worker threads started by a test, with the events that let them continue. On teardown (before the database
    pool closes) every event is set and every thread joined, so a failing assertion never leaves a worker waiting."""
    started: list[tuple] = []
    yield started
    for thread, *gates in started:
        for gate in gates:
            gate.set()
        thread.join(30)


def start(worker: Worker, sys_ctx, name: str, threads: list, *gates: threading.Event):
    [(job, token)] = worker.claim(sys_ctx)
    thread = threading.Thread(target=worker.execute, args=(sys_ctx, job, token), name=name)
    threads.append((thread, *gates))
    thread.start()
    return job, token, thread


def cancel(env, e, who="analyst"):
    return env.svc(who, lambda s: s.cancel_execution(e["id"], "no longer wanted"))


def take_over(env, name="B"):
    env.worker(name, LONG).run_once(only_tenants={env.world.a.id})


def mark_carried(admin_conn):
    """A recovery acknowledgement recorded after the job was created: the job was carried across a restore, so the
    database cannot vouch that it holds every effect intent the job wrote before the restore."""
    admin_conn.execute("INSERT INTO axiom.recovery_acknowledgements(fingerprint, acknowledged_by, note) "
                       "VALUES ('test-' || gen_random_uuid(), 'test', 'restore acknowledged after the job was created')")


class AheadWitness:
    """An external restore witness that has seen a later effect watermark than this database holds."""
    def advance(self, watermark):
        pass

    def high_water(self):
        return 10 ** 12


# ---------------------------------------------------------------------------- before dispatch is possible
@pytest.mark.parametrize("after", ["worker_resumes", "takeover"])
def test_cancel_while_paused_before_the_gate_authorizes_sending(env, admin_conn, threads, after):
    """Worker A has written the intent and is paused in its lookup, before the gate authorizes a dispatch. The
    operator cancels. Whether A resumes (and meets the cancellation at the authorization) or loses its lease and B
    takes over, nothing is sent: the execution is cancelled and its use returned, in one transaction, exactly once."""
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    at_find, proceed = threading.Event(), threading.Event()
    worker_a = Worker(env.db, [ActionExecuteHandler(paused(env, "find", at_find, proceed))], worker_id="A",
                      config=LONG)
    job, token, ta = start(worker_a, env.ctx_for("system"), "A", threads, proceed)
    assert at_find.wait(15)
    assert cancel(env, e)["state"] == "executing"                 # a running job is flagged, not settled here
    if after == "takeover":
        _expire_lease(admin_conn, job["id"])
        take_over(env)                                            # B's claim settles the cancellation
    proceed.set()
    ta.join(15)
    assert not ta.is_alive()
    assert facts(env, admin_conn, e, a) == {
        "job": "cancelled", "execution": "cancelled", "external_ref": None, "intent": "prepared",
        "reservation": "released", "uses": (1, 1), "creates": 0, "tickets": 0}
    ev = events(admin_conn, job["id"])
    assert not [r for r in ev if r["event"] == "effect_attempt"], "a dispatch was authorized after cancellation"
    if after == "takeover":
        assert [r["worker"] for r in ev if r["event"] == "cancelled"] == ["B"]
    assert second_execution(env, p, a) == "allowed"               # the use was returned, once


def test_cancel_after_an_attempt_reported_not_applied_returns_the_use(env, admin_conn):
    """The only dispatch was refused before a connection was made (definitely not applied). That attempt is
    accounted for, so the use is returned."""
    env.fake.connect_error = 1
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    env.worker("A", LONG).run_once(only_tenants={env.world.a.id})
    assert env.job(e["job_id"])["state"] == "queued"
    assert cancel(env, e)["state"] == "cancelled"
    assert facts(env, admin_conn, e, a) == {
        "job": "cancelled", "execution": "cancelled", "external_ref": None, "intent": "prepared",
        "reservation": "released", "uses": (1, 1), "creates": 1, "tickets": 0}


# ------------------------------------------------------ after dispatch is possible, before the outcome is known
@pytest.mark.parametrize("where", ["before_send", "in_provider"])
@pytest.mark.parametrize("then", ["outcome_unknown", "takeover_then_success", "success"])
def test_cancel_after_the_gate_authorized_sending(env, admin_conn, threads, where, then):
    """Worker A's gate has authorized the dispatch; A is paused either before its request leaves or while the
    provider holds it. The operator cancels. A cancellation cannot recall a request, so:

    * outcome_unknown: the acknowledgement is lost. The execution goes to reconciliation, the job waits for an
      operator, and the use stays reserved, so the single-use approval cannot authorize a fresh execution.
    * takeover_then_success: A loses its lease; B's claim parks the execution the same way. A's request then succeeds:
      the success is recorded on the intent, but A may not transition the execution. The operator adopts it.
    * success: A keeps its lease and its request succeeds; the execution succeeds rather than being cancelled."""
    env.fake = JiraStyleFake(search_lag=3600)
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    reached, proceed = threading.Event(), threading.Event()
    if where == "before_send":
        factory = paused(env, "create", reached, proceed)
    else:
        env.fake.hold_armed, reached, proceed, factory = True, env.fake.at_boundary, env.fake.release, env.adapter
    if then == "outcome_unknown":
        env.fake.lose_ack = 1
    worker_a = Worker(env.db, [ActionExecuteHandler(factory)], worker_id="A", config=LONG)
    job, token, ta = start(worker_a, env.ctx_for("system"), "A", threads, proceed)
    assert reached.wait(15)
    assert cancel(env, e)["state"] == "executing"
    if then == "takeover_then_success":
        _expire_lease(admin_conn, job["id"])
        take_over(env)
        assert facts(env, admin_conn, e, a) == {
            "job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "executing",
            "reservation": "reserved", "uses": (1, 0), "creates": 1 if where == "in_provider" else 0, "tickets": 0}
    proceed.set()
    ta.join(30)
    assert not ta.is_alive()
    got = facts(env, admin_conn, e, a)
    if then == "success":
        assert got == {"job": "succeeded", "execution": "succeeded", "external_ref": "SEC-1", "intent": "succeeded",
                       "reservation": "consumed", "uses": (1, 0), "creates": 1, "tickets": 1}
        return
    if then == "outcome_unknown":
        assert got == {"job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "unknown",
                       "reservation": "reserved", "uses": (1, 0), "creates": 1, "tickets": 1}
        detail = env.execution(e["id"])["outcome_detail"]
        assert detail["external_effect"] == "unknown" and detail["reservation"].startswith("held:")
        assert "approval use stays reserved" in env.job(e["job_id"])["operator_reason"]
        assert second_execution(env, p, a) == "refused:approval_exhausted"
        return
    # takeover_then_success: the late success is an observation; A's transition was discarded
    assert got == {"job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "succeeded",
                   "reservation": "reserved", "uses": (1, 0), "creates": 1, "tickets": 1}
    discarded = [r for r in events(admin_conn, job["id"]) if r["event"] == "execution_transition_discarded"]
    assert [d["detail"]["intended"] for d in discarded] == ["succeeded"] and discarded[0]["lease_token"] == token
    assert second_execution(env, p, a) == "refused:approval_exhausted"
    env.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="SEC-1 carries the label",
                                           external_ref="SEC-1"))
    assert facts(env, admin_conn, e, a) == {
        "job": "succeeded", "execution": "succeeded", "external_ref": "SEC-1", "intent": "succeeded",
        "reservation": "consumed", "uses": (1, 0), "creates": 1, "tickets": 1}


def test_cancel_with_an_earlier_dispatch_still_in_flight_holds_the_use(env, admin_conn, threads):
    """The provider fences, so after A's request was held and A lost its lease, B repeats the dispatch; B's request
    is refused before a connection is made (not applied) and the intent returns to prepared. A's request is still in
    flight, so a prepared intent alone is not evidence that nothing was sent: the cancellation must hold the use.
    A's request then lands and creates the ticket; returning the use would have let the approval authorize a
    second ticket under a new operation key, which provider fencing cannot stop."""
    env.fake = JiraStyleFake(search_lag=3600, fencing=True)
    env.caps = FENCED
    env.fake.hold_armed = True
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    job, token, ta = start(env.worker("A", LONG), env.ctx_for("system"), "A", threads, env.fake.release)
    assert env.fake.at_boundary.wait(15)
    _expire_lease(admin_conn, job["id"])
    env.fake.connect_error = 1
    take_over(env)                                                # B: repeat refused before sending -> retry
    assert (env.job(job["id"])["state"], facts(env, admin_conn, e, a)["intent"]) == ("queued", "prepared")
    cancel(env, e)
    held = facts(env, admin_conn, e, a)
    env.fake.release.set()
    ta.join(30)
    assert not ta.is_alive()
    assert held == {"job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "prepared",
                    "reservation": "reserved", "uses": (1, 0), "creates": 2, "tickets": 0}
    assert second_execution(env, p, a) == "refused:approval_exhausted"
    assert facts(env, admin_conn, e, a)["tickets"] == 1           # A's request did create the ticket


# --------------------------------------------------------------------------- recorded success and cancel
@pytest.mark.parametrize("via", ["claim", "operator_cancel"])
def test_a_recorded_success_settles_the_cancellation_as_succeeded(env, admin_conn, hooked_gate, threads, via):
    """The success is recorded on the intent before the cancellation is settled, but the execution has not been
    transitioned: A lost its lease right after its gate recorded the success (claim), or B parked the execution while
    A's request was in flight and the success landed afterwards (operator_cancel). Settling the cancellation reconciles
    the execution from the recorded success instead of marking it cancelled."""
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    sys_ctx = env.ctx_for("system")
    if via == "claim":
        gate_done, proceed = threading.Event(), threading.Event()
        hooked_gate["A"] = lambda jc, outcome: (gate_done.set(), proceed.wait(15))
        job, token, ta = start(env.worker("A", LONG), sys_ctx, "A", threads, proceed)
        assert gate_done.wait(15)                                 # the success is on the intent
        _expire_lease(admin_conn, job["id"])
        cancel(env, e)                                            # the job still shows running: flagged
        take_over(env)                                            # B's claim settles from the record
        proceed.set()
    else:
        env.fake = JiraStyleFake(search_lag=3600)
        env.fake.hold_armed = True
        job, token, ta = start(env.worker("A", LONG), sys_ctx, "A", threads, env.fake.release)
        assert env.fake.at_boundary.wait(15)
        _expire_lease(admin_conn, job["id"])
        take_over(env)                                            # B parks: cannot tell, cannot deduplicate
        env.fake.release.set()
        ta.join(30)
        assert facts(env, admin_conn, e, a)["intent"] == "succeeded"
        assert env.execution(e["id"])["state"] == "reconciling"
        cancel(env, e)                                            # a parked job: settled now
    ta.join(30)
    assert not ta.is_alive()
    assert facts(env, admin_conn, e, a) == {
        "job": "succeeded", "execution": "succeeded", "external_ref": "SEC-1", "intent": "succeeded",
        "reservation": "consumed", "uses": (1, 0), "creates": 1, "tickets": 1}
    refs = env.execution(e["id"])["external_references"]
    assert [(r["external_id"], r["verified"]) for r in refs] == [("SEC-1", False)]   # from the record, unverified


# --------------------------------------------------------------- operator reconciliation and accounting
@pytest.mark.parametrize("fault,resolution", [("lose_ack", "adopt"), ("fail_unprocessed", "not_applied"),
                                              ("fail_unprocessed", "abandon")])
def test_operator_reconciles_a_held_cancellation(env, admin_conn, fault, resolution):
    """The first attempt's outcome is unknown and the job is queued to reconcile by lookup; the operator cancels. The
    cancellation is held (the use stays reserved). The operator then establishes the outcome:

    * adopt (the ticket exists): the execution succeeds, the use is consumed.
    * not_applied (the operator found nothing): the cancellation now settles; cancelled and the use returned.
    * abandon (the operator cannot tell): the execution fails, the use is consumed and the record says the effect is
      unknown."""
    env.fake = JiraStyleFake(search_lag=3600)
    setattr(env.fake, fault, 1)
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    env.worker("A", LONG).run_once(only_tenants={env.world.a.id})
    assert env.job(e["job_id"])["state"] == "queued"
    assert cancel(env, e)["state"] == "reconciling"
    tickets = 1 if fault == "lose_ack" else 0
    assert facts(env, admin_conn, e, a) == {
        "job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "unknown",
        "reservation": "reserved", "uses": (1, 0), "creates": 1, "tickets": tickets}
    assert second_execution(env, p, a) == "refused:approval_exhausted"
    env.svc("admin", lambda s: s.reconcile(e["id"], resolution=resolution, rationale="checked the tracker",
                                           external_ref="SEC-1" if resolution == "adopt" else None))
    env.drive(admin_conn, e["job_id"], worker=env.worker("C", LONG))
    expected = {
        "adopt": {"job": "succeeded", "execution": "succeeded", "external_ref": "SEC-1", "intent": "reconciled",
                  "reservation": "consumed", "uses": (1, 0)},
        "not_applied": {"job": "cancelled", "execution": "cancelled", "external_ref": None, "intent": "prepared",
                        "reservation": "released", "uses": (1, 1)},
        "abandon": {"job": "failed", "execution": "failed", "external_ref": None, "intent": "abandoned",
                    "reservation": "consumed", "uses": (1, 0)}}[resolution]
    assert facts(env, admin_conn, e, a) == {**expected, "creates": 1, "tickets": tickets}
    assert second_execution(env, p, a) == ("allowed" if resolution == "not_applied" else "refused:approval_exhausted")
    if resolution == "abandon":
        assert env.execution(e["id"])["outcome_detail"]["external_effect"] == "unknown"


@pytest.mark.parametrize("case", ["cancel_queued", "cancel_parked", "abandon_witness_park"])
def test_restore_doubt_keeps_the_use_reserved(env, admin_conn, case):
    """A restored database may have lost intents, so a missing or prepared intent is not evidence that nothing was
    sent.

    * cancel_queued: the job was carried across a restore and not yet run; the cancellation is held.
    * cancel_parked: the gate parked the carried job; the cancellation is held; the operator's not_applied then
      settles it (cancelled, use returned).
    * abandon_witness_park: the restore witness parked the job before any intent was written; abandoning it fails the
      execution with the use consumed and the effect recorded as unknown, so the approval cannot authorize a
      duplicate."""
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    if case == "abandon_witness_park":
        w = Worker(env.db, [ActionExecuteHandler(env.adapter)], worker_id="R", config=LONG, witness=AheadWitness())
        [(job, token)] = w.claim(env.ctx_for("system"))
        w.execute(env.ctx_for("system"), job, token)              # the gate's own witness check parks it
        assert (env.job(e["job_id"])["state"], env.execution(e["id"])["intent"]) == ("needs_operator", None)
        env.svc("admin", lambda s: s.reconcile(e["id"], resolution="abandon", rationale="cannot tell"))
        assert facts(env, admin_conn, e, a) == {
            "job": "failed", "execution": "failed", "external_ref": None, "intent": None,
            "reservation": "consumed", "uses": (1, 0), "creates": 0, "tickets": 0}
        assert env.execution(e["id"])["outcome_detail"]["external_effect"] == "unknown"
        assert second_execution(env, p, a) == "refused:approval_exhausted"
        return
    mark_carried(admin_conn)
    if case == "cancel_parked":
        env.drive(admin_conn, e["job_id"], worker=env.worker("R", LONG))
        assert env.job(e["job_id"])["state"] == "needs_operator"
    cancel(env, e)
    assert facts(env, admin_conn, e, a) == {
        "job": "needs_operator", "execution": "reconciling", "external_ref": None,
        "intent": "prepared" if case == "cancel_parked" else None,
        "reservation": "reserved", "uses": (1, 0), "creates": 0, "tickets": 0}
    assert "predates the latest recovery acknowledgement" in env.job(e["job_id"])["operator_reason"]
    assert second_execution(env, p, a) == "refused:approval_exhausted"
    if case == "cancel_parked":
        env.svc("admin", lambda s: s.reconcile(e["id"], resolution="not_applied", rationale="nothing in the tracker"))
        env.drive(admin_conn, e["job_id"], worker=env.worker("C", LONG))
        assert facts(env, admin_conn, e, a) == {
            "job": "cancelled", "execution": "cancelled", "external_ref": None, "intent": "prepared",
            "reservation": "released", "uses": (1, 1), "creates": 0, "tickets": 0}


# ----------------------------------------------------------------------------------- stale worker
def test_stale_worker_cannot_return_the_use_after_takeover(env, admin_conn, hooked_gate, threads):
    """The job was carried across a restore. Worker A's gate meets the cancellation and returns without sending; A
    is paused before its final write and loses its lease. B's claim settles the cancellation: the database cannot
    vouch for its effect records, so the use stays reserved. When A resumes, its attempt to finish the job (which
    would have returned the use: the intent is still prepared) is discarded."""
    env.fake = JiraStyleFake(search_lag=3600)
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    mark_carried(admin_conn)
    at_find, proceed_find = threading.Event(), threading.Event()
    gate_done, proceed = threading.Event(), threading.Event()
    hooked_gate["A"] = lambda jc, outcome: (gate_done.set(), proceed.wait(15))
    worker_a = Worker(env.db, [ActionExecuteHandler(paused(env, "find", at_find, proceed_find))], worker_id="A",
                      config=LONG)
    job, token, ta = start(worker_a, env.ctx_for("system"), "A", threads, proceed_find, proceed)
    assert at_find.wait(15)
    cancel(env, e)
    proceed_find.set()
    assert gate_done.wait(15)                                     # A's gate returned "cancelled before the effect"
    _expire_lease(admin_conn, job["id"])
    take_over(env)
    proceed.set()
    ta.join(15)
    assert not ta.is_alive()
    assert facts(env, admin_conn, e, a) == {
        "job": "needs_operator", "execution": "reconciling", "external_ref": None, "intent": "prepared",
        "reservation": "reserved", "uses": (1, 0), "creates": 0, "tickets": 0}
    ev = events(admin_conn, job["id"])
    assert [r["worker"] for r in ev if r["event"] == "cancel_settled_needs_operator"] == ["B"]
    stale = [r for r in ev if r["event"] in ("stale_result_discarded", "execution_transition_discarded")]
    assert stale and all(r["lease_token"] == token for r in stale)
    assert second_execution(env, p, a) == "refused:approval_exhausted"


# ------------------------------------------------------------------------- generic job operations
@pytest.mark.parametrize("operation", ["cancel", "resolve_effect"])
def test_generic_job_operations_do_not_bypass_the_execution(env, admin_conn, operation):
    """Cancelling or resolving an action job through the generic job operations would change the job without its
    execution and approval use. They are refused; the action execution endpoints settle both together."""
    env.fake.lose_ack, env.fake.search_lag = 1, 3600
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    if operation == "resolve_effect":
        env.drive(admin_conn, e["job_id"])
    before = facts(env, admin_conn, e, a)
    admin = env.ctx_for("admin")
    with pytest.raises(Conflict) as err:
        with env.db.tenant_tx(admin) as conn:
            ops = JobOperations(conn, admin, Authorizer(conn, admin))
            if operation == "cancel":
                ops.request_cancel(e["job_id"], "stop")
            else:
                ops.resolve_effect(e["job_id"], resolution="abandon", rationale="cannot tell")
    assert err.value.code == "settled_with_aggregate"
    assert facts(env, admin_conn, e, a) == before


# ------------------------------------------------------------- operator adoption the gate cannot verify
@pytest.mark.parametrize("park", ["witness_no_intent", "verification_failed"])
def test_adopt_without_a_verifiable_record_is_refused(env, admin_conn, park):
    """With no open intent left, adopting does not re-run the gate, so nothing would verify the operator's reference.
    Finishing the execution from it is refused when no success is recorded (the restore witness parked the job before
    any intent existed) or when the recorded object failed verification; nothing changes and the use stays reserved."""
    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)
    if park == "witness_no_intent":
        w = Worker(env.db, [ActionExecuteHandler(env.adapter)], worker_id="R", config=LONG, witness=AheadWitness())
        [(job, token)] = w.claim(env.ctx_for("system"))
        w.execute(env.ctx_for("system"), job, token)
        ref = "SEC-7"
    else:
        def factory(*args):
            adapter = env.adapter()
            adapter.verify = lambda ref, key: False
            return adapter
        Worker(env.db, [ActionExecuteHandler(factory)], worker_id="R", config=LONG).run_once(
            only_tenants={env.world.a.id})
        ref = "SEC-1"
    before = facts(env, admin_conn, e, a)
    assert (before["job"], before["execution"], before["reservation"]) == ("needs_operator", "reconciling", "reserved")
    with pytest.raises(Conflict) as err:
        env.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="looks right", external_ref=ref))
    assert err.value.code == "effect_evidence_missing"
    assert facts(env, admin_conn, e, a) == before
