"""The same action-protocol failure modes against all three workflow adapters (all fixture-tested only).

Jira-style, ServiceNow-style and GitHub Issues adapters each declare no deduplication and a lookup that is not proof
of absence, so the expected behaviour is identical: one ticket per execution, adopt on a lookup hit, park (never
re-create) after an uncertain create the lookup cannot see, and externally closed tickets never move the case.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

import pytest

from axiom.domains.actions.sync import TicketSyncHandler
from axiom.errors import ValidationFailed
from axiom.ingestion.sync import SyncService
from axiom.integrations.github_issues import GitHubIssueAdapter
from axiom.integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from axiom.integrations.servicenow import ServiceNowTicketAdapter
from axiom.jobs import Worker, WorkerConfig, enqueue

from .jira_fake import JiraStyleFake
from .test_actions import FAST, Env
from .workflow_fakes import GitHubFake, ServiceNowFake

pytestmark = pytest.mark.db


@dataclass
class Kind:
    adapter: str
    base_url: str
    config: dict
    payload: dict
    make_fake: Callable
    make_adapter: Callable
    refs: Callable
    close: Callable


KINDS = {
    "jira_style": Kind("jira_style", "https://tracker.test.invalid", {},
                       {"project_key": "SEC", "summary": "Patch payments", "description": "d", "labels": []},
                       lambda lag: JiraStyleFake(search_lag=lag),
                       lambda f: JiraStyleTicketAdapter(JiraStyleClient("https://tracker.test.invalid",
                                                                        lambda: ("u", "t"), transport=f.transport())),
                       lambda f: f.keys(), lambda f, ref: f.set_status(ref, "Done", "done")),
    "servicenow": Kind("servicenow", "https://instance.test.invalid", {"table": "incident"},
                       {"summary": "Patch payments", "description": "d", "labels": []},
                       lambda lag: ServiceNowFake(lookup_lag=lag),
                       lambda f: ServiceNowTicketAdapter("https://instance.test.invalid", lambda: ("u", "t"),
                                                         transport=f.transport()),
                       lambda f: f.refs(), lambda f, ref: f.set_state(ref, "7")),
    "github_issues": Kind("github_issues", "https://api.github.test.invalid", {"repo": "acme/payments"},
                          {"summary": "Patch payments", "description": "d", "labels": ["security"]},
                          lambda lag: GitHubFake(lookup_lag=lag),
                          lambda f: GitHubIssueAdapter("acme/payments", lambda: "tok",
                                                       api="https://api.github.test.invalid", transport=f.transport()),
                          lambda f: f.refs(), lambda f, ref: f.close(int(ref.split("#")[1]))),
}


@pytest.fixture(params=list(KINDS))
def wf(request, db, world, ctx_for, dbinfo, run):
    k = KINDS[request.param]
    env = Env(db, world, ctx_for, dbinfo, run)
    env.connection = SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter=k.adapter, scope_id=world.a.project, display_name=k.adapter,
        base_url=k.base_url, credential_ref="secretref:test/wf", config=k.config)
    env.kind = k
    env.wfake = k.make_fake(0.0)
    env.adapter = lambda *_: k.make_adapter(env.wfake)
    return env


def propose_and_execute(env):
    p = env.propose(env.kind.payload)
    return env.execute(p, env.approve(p))


def test_one_verified_ticket_with_provider_recorded(wf, admin_conn):
    e = propose_and_execute(wf)
    assert wf.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    got = wf.execution(e["id"])
    [ref] = got["external_references"]
    assert ref["provider"] == wf.kind.adapter and ref["verified"] and ref["how"] == "created"
    assert wf.kind.refs(wf.wfake) == [got["external_ref"]] and wf.wfake.create_requests == 1


def test_lost_ack_unseen_by_lookup_parks_without_recreating(wf, admin_conn):
    wf.wfake = wf.kind.make_fake(3600)
    wf.wfake.lose_ack = 1
    e = propose_and_execute(wf)
    assert wf.drive(admin_conn, e["job_id"])["state"] == "needs_operator"
    assert wf.wfake.create_requests == 1 and len(wf.kind.refs(wf.wfake)) == 1
    ref = wf.kind.refs(wf.wfake)[0]
    wf.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", external_ref=ref,
                                          rationale="found the record carrying our operation key"))
    assert wf.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert wf.execution(e["id"])["external_references"][0]["how"] == "adopted_by_operator"
    assert wf.wfake.create_requests == 1


def test_lost_ack_seen_by_lookup_is_adopted(wf, admin_conn):
    wf.wfake.lose_ack = 1
    e = propose_and_execute(wf)
    assert wf.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    assert wf.execution(e["id"])["external_references"][0]["how"] == "adopted_by_lookup"
    assert wf.wfake.create_requests == 1


def test_stale_worker_past_the_boundary_new_worker_parks(wf, admin_conn):
    wf.wfake = wf.kind.make_fake(3600)
    wf.wfake.hold_armed = True
    e = propose_and_execute(wf)
    a = wf.worker("A", WorkerConfig(lease_seconds=0.5, step_timeout_seconds=30, max_backoff_seconds=0.01))
    [(job, token)] = a.claim(wf.ctx_for("system"))
    t = threading.Thread(target=a.execute, args=(wf.ctx_for("system"), job, token))
    t.start()
    assert wf.wfake.at_boundary.wait(10)
    admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second',
                                 step_deadline_at = clock_timestamp() - interval '1 second',
                                 record_version = record_version + 1 WHERE id = %s""", (job["id"],))
    wf.worker("B").run_once(only_tenants={wf.world.a.id})
    assert wf.job(job["id"])["state"] == "needs_operator"
    wf.wfake.release.set()
    t.join(30)
    assert wf.wfake.create_requests == 1 and len(wf.kind.refs(wf.wfake)) == 1


def test_externally_closed_ticket_never_moves_the_case(wf, admin_conn):
    e = propose_and_execute(wf)
    wf.drive(admin_conn, e["job_id"])
    ref = wf.execution(e["id"])["external_ref"]
    wf.kind.close(wf.wfake, ref)
    sys = wf.ctx_for("system")
    with wf.db.tenant_tx(sys) as conn:
        enqueue(conn, sys, kind="actions.ticket_sync", version=1, payload={})
    before = wf.run(wf.ctx_for("analyst"), lambda s: s.cases.get(wf.case["id"]))
    Worker(wf.db, [TicketSyncHandler(wf.adapter)], config=FAST).run_once(only_tenants={wf.world.a.id})
    with wf.db.tenant_tx(sys) as conn:
        cats = [r["status_category"] for r in conn.execute("SELECT status_category FROM axiom.external_ticket_states")]
    after = wf.run(wf.ctx_for("analyst"), lambda s: s.cases.get(wf.case["id"]))
    assert cats == ["done"]
    assert (after["workflow"], after["record_version"]) == (before["workflow"], before["record_version"])


def test_payload_must_fit_the_connection(wf):
    if wf.kind.adapter == "jira_style":
        with pytest.raises(ValidationFailed):
            wf.propose({"summary": "no project"})
    else:
        with pytest.raises(ValidationFailed):
            wf.propose({**wf.kind.payload, "project_key": "SEC"})
