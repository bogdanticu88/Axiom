"""Opt-in: the action protocol against the real GitHub Issues REST API, on a disposable private repository.

Skipped unless explicitly enabled. Running it creates issues in the named repository, so it needs authorisation:

    AXIOM_TEST_GITHUB_ISSUES=1
    AXIOM_TEST_GITHUB_REPO=<owner>/<name>          # a private, disposable repository with Issues enabled
    AXIOM_TEST_GITHUB_APPROVED_REPO=<owner>/<name> # the repository approved for this run; must equal the above
    AXIOM_TEST_GITHUB_TOKEN_FILE=<absolute path>   # fine-grained token, file mode 0600, read via secretref:file/
    AXIOM_TEST_GITHUB_MODE=normal | readonly | revoked   (default normal)

Before any write the test checks that GitHub answers for exactly that repository (no redirect, same full name) and
that it is private with Issues enabled. Every request, the platform's and the test's own, may go only to the API host;
a redirect is never followed, so the token cannot be forwarded to another host.

``normal`` needs Issues read and write on that one repository and creates 4 issues (scenarios marked [creates 1]),
closing them at the end. ``readonly`` (the same token edited to Issues read-only) and ``revoked`` (after the token
was deleted) create none. The token is never printed: requests are recorded as method, path and status only, and each
test checks the token value appears in no log line and no database row it wrote.

What is the provider's behaviour and what is simulated here:

* Provider, tested directly: issue creation and its response, the issue list with ``since`` (lookup) seeing a new
  issue, reading an issue back (verification), closing, a permission refusal (readonly), a revoked token (revoked).
* Simulated locally, never by sending extra requests: a lost response (the request is sent once and its response
  discarded), a stale issue index (a created issue hidden from the list the adapter sees), a worker paused before
  its request leaves, a lease expiry (database clock), an unreadable credential file.

Nothing here makes creation exactly-once; the tests check that the platform sends at most one create per operation
and never a second one after an uncertain outcome.
"""
from __future__ import annotations

import os
import stat
import threading
import uuid
from pathlib import Path

import httpx
import pytest

ENABLED = os.environ.get("AXIOM_TEST_GITHUB_ISSUES") == "1"
REPO = os.environ.get("AXIOM_TEST_GITHUB_REPO", "")
APPROVED_REPO = os.environ.get("AXIOM_TEST_GITHUB_APPROVED_REPO", "")
TOKEN_FILE = os.environ.get("AXIOM_TEST_GITHUB_TOKEN_FILE", "")
MODE = os.environ.get("AXIOM_TEST_GITHUB_MODE", "normal")
API = "https://api.github.com"
RUN = uuid.uuid4().hex[:8]

pytestmark = [pytest.mark.db, pytest.mark.skipif(
    not (ENABLED and REPO and TOKEN_FILE),
    reason="real GitHub Issues test is opt-in (AXIOM_TEST_GITHUB_ISSUES=1, AXIOM_TEST_GITHUB_REPO, "
           "AXIOM_TEST_GITHUB_TOKEN_FILE)")]

CREATED: list[int] = []        # issue numbers this run created, closed at the end (normal mode)


def only(mode: str):
    return pytest.mark.skipif(MODE != mode, reason=f"runs in AXIOM_TEST_GITHUB_MODE={mode}")


# ----------------------------------------------------------------------------------------------- transport
class Held:
    """A request held before it leaves. It is sent only if the test calls ``send()``; a failed test calls
    ``withdraw()``, and if neither happens within the wait the request is withdrawn too. A withdrawn request is
    refused locally as a connection failure, so it never reaches GitHub."""

    def __init__(self, thread: str, method: str):
        self.thread, self.method = thread, method
        self.reached, self.decided, self.allowed = threading.Event(), threading.Event(), False

    def send(self):
        self.allowed = True
        self.decided.set()

    def withdraw(self):
        self.allowed = False
        self.decided.set()


def _api_host() -> str:
    return httpx.URL(API).host


class Recorder(httpx.BaseTransport):
    """The real HTTPS transport, recording method, path and status (never headers or bodies), with local
    simulations: hold a request before it leaves, discard one create response after GitHub processed it, hide
    issues from the list the adapter reads. It refuses any request to a host other than the API host."""

    def __init__(self):
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        self.inner = httpx.HTTPTransport(proxy=proxy) if proxy else httpx.HTTPTransport()
        self.log: list[tuple[str, str, int | str]] = []
        self.lose_next_create = False
        self.hidden: set[int] = set()
        self.discarded: list[int] = []
        self.hold: Held | None = None
        self.refusals: list[dict] = []

    def creates(self) -> int:
        return sum(1 for m, p, _ in self.log if m == "POST" and p.endswith("/issues"))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        if request.url.host != _api_host():
            raise AssertionError(f"refusing a request to {request.url.host}: only {_api_host()} is allowed")
        if self.hold and threading.current_thread().name == self.hold.thread and method == self.hold.method:
            held, self.hold = self.hold, None
            held.reached.set()
            if not held.decided.wait(60) or not held.allowed:
                self.log.append((method, path, "withdrawn"))
                raise httpx.ConnectError("held request withdrawn by the test; it was not sent", request=request)
        try:
            response = self.inner.handle_request(request)
        except httpx.HTTPError as exc:
            self.log.append((method, path, type(exc).__name__))
            raise
        response.read()
        self.log.append((method, path, response.status_code))
        if response.status_code in (401, 403):
            self.refusals.append({"method": method, "status": response.status_code,
                                  "accepted_permissions": response.headers.get("x-accepted-github-permissions"),
                                  "message": (response.json() or {}).get("message") if response.content else None})
        if method == "POST" and path.endswith("/issues") and response.status_code == 201:
            number = response.json()["number"]
            CREATED.append(number)
            if self.lose_next_create:
                self.lose_next_create = False
                self.discarded.append(number)
                response.close()
                raise httpx.ReadTimeout("response discarded by the test (simulated lost acknowledgement)",
                                        request=request)
        if method == "GET" and path.endswith("/issues") and self.hidden and response.status_code == 200:
            items = [i for i in response.json() if i["number"] not in self.hidden]
            return httpx.Response(200, json=items, request=request)
        return response


# ------------------------------------------------------------------------------------------------ fixtures
def _token() -> str:
    return Path(TOKEN_FILE).read_text().strip()


def _direct(method: str, path: str, **kw) -> httpx.Response:
    """A request outside the platform, for preconditions and cleanup only. Never follows a redirect."""
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    with httpx.Client(proxy=proxy, timeout=20.0, follow_redirects=False) as c:
        return c.request(method, f"{API}{path}", headers={
            "Authorization": f"Bearer {_token()}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}, **kw)


@pytest.fixture(scope="module", autouse=True)
def target_repository():
    path = Path(TOKEN_FILE)
    assert path.is_absolute() and path.is_file(), "AXIOM_TEST_GITHUB_TOKEN_FILE must be an absolute path to a file"
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "the token file must not be readable by group or others"
    assert REPO and REPO == APPROVED_REPO, "AXIOM_TEST_GITHUB_REPO must equal AXIOM_TEST_GITHUB_APPROVED_REPO"
    if MODE == "revoked":
        yield
        return
    r = _direct("GET", f"/repos/{REPO}")
    assert r.status_code == 200, f"cannot read {REPO}: HTTP {r.status_code} (a redirect is not followed)"
    repo = r.json()
    assert repo["full_name"].lower() == REPO.lower(), "GitHub answered for a different repository"
    assert repo["private"] is True, "refusing to write to a repository that is not private"
    assert repo["has_issues"] is True, "the repository has Issues disabled"
    yield
    for number in CREATED:                                   # cleanup: close what this run created
        _direct("PATCH", f"/repos/{REPO}/issues/{number}", json={"state": "closed", "state_reason": "not_planned"})
    print(f"\nGITHUB_ISSUES_CREATED run={RUN} repo={REPO} numbers={CREATED} (closed; delete them or the repository)")


@pytest.fixture()
def gh(db, world, ctx_for, dbinfo, run, admin_conn, tmp_path, monkeypatch, caplog):
    from axiom.domains.actions.jobs import ActionExecuteHandler
    from axiom.ingestion.sync import SyncService
    from axiom.integrations.github_issues import GitHubIssueAdapter
    from axiom.jobs import Worker, WorkerConfig
    from axiom.jobs.witness import FileWitness

    from .test_actions import Env
    monkeypatch.setenv("AXIOM_SECRET_FILE_DIRS", str(Path(TOKEN_FILE).parent))
    env = Env(db, world, ctx_for, dbinfo, run)
    env.connection = SyncService(db, None, None).create_connection(
        ctx_for("admin"), adapter="github_issues", scope_id=world.a.project, display_name="github integration test",
        base_url=None, credential_ref=f"secretref:file{Path(TOKEN_FILE)}", config={"repo": REPO})
    env.recorder = Recorder()

    def factory(connection, secrets):                   # default_adapter_factory's github branch, plus the recorder
        ref = connection["credential_ref"]
        return GitHubIssueAdapter(connection["config"]["repo"], lambda: secrets.resolve(ref),
                                  api=connection["base_url"] or API, transport=env.recorder)
    env.factory = factory
    row = admin_conn.execute("SELECT last_value, is_called FROM axiom.effect_watermark_seq").fetchone()
    mark = int(row["last_value"]) if row["is_called"] else 0
    env.witness_dir = tmp_path / "witness"
    if mark:
        FileWitness(env.witness_dir, "seed").advance(mark)
    config = WorkerConfig(lease_seconds=60, step_timeout_seconds=120, max_backoff_seconds=0.01)
    env.make_worker = lambda name: Worker(db, [ActionExecuteHandler(factory)], worker_id=name, config=config,
                                          witness=FileWitness(env.witness_dir, name))
    env.payload = lambda scenario: {"summary": f"Axiom integration test {RUN} {scenario}",
                                    "description": "Synthetic issue created by the Axiom opt-in integration test. "
                                                   "No client data.", "labels": []}
    yield env
    # The checks below compare booleans and counts only, so a failure cannot print the token itself.
    secret = _token()
    in_logs = secret in caplog.text
    assert not in_logs, "the token appeared in a log record"
    leaked = admin_conn.execute(
        """SELECT (SELECT count(*) FROM axiom.job_events WHERE detail::text LIKE %(s)s)
                + (SELECT count(*) FROM axiom.action_executions WHERE outcome_detail::text LIKE %(s)s)
                + (SELECT count(*) FROM axiom.effect_intents WHERE coalesce(last_error, '') LIKE %(s)s) AS n""",
        {"s": f"%{secret}%"}).fetchone()["n"]
    del secret
    assert leaked == 0, "the token appeared in a database record"
    print(f"\nREQUESTS {env.recorder.log}")


def facts(env, admin_conn, e, a) -> dict:
    got = env.execution(e["id"])
    approval = admin_conn.execute("SELECT uses_reserved, uses_released FROM axiom.approvals WHERE id = %s",
                                  (a["id"],)).fetchone()
    res = admin_conn.execute("SELECT status FROM axiom.approval_reservations WHERE execution_id = %s",
                             (e["id"],)).fetchone()["status"]
    refs = got["external_references"]
    return {"job": env.job(e["job_id"])["state"], "execution": got["state"], "external_ref": got["external_ref"],
            "intent": got["intent"]["state"] if got["intent"] else None, "reservation": res,
            "uses": (approval["uses_reserved"], approval["uses_released"]),
            "how": refs[0]["how"] if refs else None, "verified": refs[0]["verified"] if refs else None,
            "creates": env.recorder.creates()}


def issues_with_marker(e) -> list[int]:
    """Issues in the repository whose body carries this execution's operation marker (read directly)."""
    from axiom.integrations.github_issues import MARKER
    marker = MARKER + e["external_operation_id"]
    found, page = [], 1
    while True:
        r = _direct("GET", f"/repos/{REPO}/issues", params={"state": "all", "per_page": 100, "page": page})
        r.raise_for_status()
        items = r.json()
        found += [i["number"] for i in items if marker in (i.get("body") or "").splitlines()]
        if len(items) < 100:
            return found
        page += 1


def drive(env, admin_conn, e, passes=6):
    w = env.make_worker("w")
    for _ in range(passes):
        if env.job(e["job_id"])["state"] not in ("queued", "waiting", "running"):
            break
        admin_conn.execute("UPDATE axiom.jobs SET due_at = clock_timestamp(), record_version = record_version + 1 "
                           "WHERE id = %s AND state IN ('queued', 'waiting')", (e["job_id"],))
        w.run_once(only_tenants={env.world.a.id})
    return env.job(e["job_id"])


def start(env, name, e):
    worker = env.make_worker(name)
    [(job, token)] = worker.claim(env.ctx_for("system"))
    t = threading.Thread(target=worker.execute, args=(env.ctx_for("system"), job, token), name=name)
    t.start()
    return job, token, t


def expire(admin_conn, job_id):
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                       "record_version = record_version + 1 WHERE id = %s", (job_id,))


# ----------------------------------------------------------------------------------------- normal mode
@only("normal")
def test_one_approved_action_creates_one_issue_and_records_its_reference(gh, admin_conn):
    """[creates 1] Provider: create, lookup (a miss before the create), read back for verification."""
    p = gh.propose(gh.payload("one-issue"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    assert drive(gh, admin_conn, e)["state"] == "succeeded"
    got = facts(gh, admin_conn, e, a)
    [number] = issues_with_marker(e)
    assert got == {"job": "succeeded", "execution": "succeeded", "external_ref": f"{REPO}#{number}",
                   "intent": "succeeded", "reservation": "consumed", "uses": (1, 0), "how": "created",
                   "verified": True, "creates": 1}


@only("normal")
def test_replaying_after_a_lost_response_does_not_create_another_issue(gh, admin_conn):
    """[creates 1] The create reaches GitHub once; its response is discarded locally (a lost acknowledgement). The
    next attempt replays the operation: the gate looks the issue up instead of creating. Provider behaviour observed:
    whether the list already shows the new issue. If it does, it is adopted; if not, the job parks and the operator
    adopts the issue found in the repository. Either way there is one create request and one issue."""
    gh.recorder.lose_next_create = True
    p = gh.propose(gh.payload("lost-response"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    job = drive(gh, admin_conn, e)
    observed = "adopted_by_lookup" if job["state"] == "succeeded" else job["state"]
    print(f"\nLOOKUP_AFTER_LOST_RESPONSE {observed}")
    if job["state"] == "needs_operator":
        [number] = issues_with_marker(e)
        gh.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="found by marker",
                                              external_ref=f"{REPO}#{number}"))
        drive(gh, admin_conn, e)
    [number] = issues_with_marker(e)
    got = facts(gh, admin_conn, e, a)
    assert got["creates"] == 1, "a second create was sent after an uncertain outcome"
    assert (got["execution"], got["external_ref"], got["reservation"], got["uses"]) == (
        "succeeded", f"{REPO}#{number}", "consumed", (1, 0))
    assert gh.recorder.discarded == [number]


@only("normal")
def test_uncertain_create_unseen_by_lookup_parks_for_the_operator(gh, admin_conn):
    """[creates 1] As above, and the new issue is hidden from the list the adapter reads (a stale index, simulated
    locally). The gate must not create again: it parks; the operator adopts the issue; verification reads it back
    from GitHub."""
    gh.recorder.lose_next_create = True
    p = gh.propose(gh.payload("stale-index"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    w = gh.make_worker("w")
    w.run_once(only_tenants={gh.world.a.id})                  # create sent, response discarded
    gh.recorder.hidden.update(gh.recorder.discarded)
    job = drive(gh, admin_conn, e)
    parked = facts(gh, admin_conn, e, a)
    assert (job["state"], parked["execution"], parked["reservation"], parked["creates"]) == (
        "needs_operator", "reconciling", "reserved", 1)
    [number] = issues_with_marker(e)
    gh.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="found by marker",
                                          external_ref=f"{REPO}#{number}"))
    drive(gh, admin_conn, e)
    got = facts(gh, admin_conn, e, a)
    assert got == {"job": "succeeded", "execution": "succeeded", "external_ref": f"{REPO}#{number}",
                   "intent": "reconciled", "reservation": "consumed", "uses": (1, 0), "how": "adopted_by_operator",
                   "verified": True, "creates": 1}


@only("normal")
def test_cancellation_before_dispatch_returns_the_use(gh, admin_conn):
    """Creates nothing. Worker A is paused at its lookup (before the gate authorizes a create); the operator cancels;
    A resumes, meets the cancellation and its final write returns the use after the witness check."""
    p = gh.propose(gh.payload("cancel-before"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    held = gh.recorder.hold = Held("A", "GET")
    job, token, t = start(gh, "A", e)
    try:
        assert held.reached.wait(30)
        gh.svc("analyst", lambda s: s.cancel_execution(e["id"], "no longer wanted"))
        held.send()
    except BaseException:
        held.withdraw()                     # a failed test never lets the held request leave
        raise
    finally:
        t.join(60)
    got = facts(gh, admin_conn, e, a)
    assert (got["job"], got["execution"], got["reservation"], got["uses"], got["creates"]) == (
        "cancelled", "cancelled", "released", (1, 1), 0)
    assert issues_with_marker(e) == []


@only("normal")
def test_cancellation_and_takeover_after_dispatch_is_authorized(gh, admin_conn):
    """[creates 1] Worker A is paused after the gate authorized its create, before the request leaves. The operator
    cancels; A's lease expires; worker B's claim holds the cancellation (the use stays reserved). A's request is then
    sent and GitHub creates the issue: the success is recorded, but A may not transition the execution. The operator
    adopts; the use is consumed and the single-use approval cannot run again."""
    from axiom.errors import Conflict
    p = gh.propose(gh.payload("cancel-takeover"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    held = gh.recorder.hold = Held("A", "POST")
    job, token, t = start(gh, "A", e)
    try:
        assert held.reached.wait(30)
        gh.svc("analyst", lambda s: s.cancel_execution(e["id"], "no longer wanted"))
        expire(admin_conn, job["id"])
        gh.make_worker("B").run_once(only_tenants={gh.world.a.id})
        before = facts(gh, admin_conn, e, a)
        assert (before["job"], before["execution"], before["reservation"], before["uses"], before["creates"]) == (
            "needs_operator", "reconciling", "reserved", (1, 0), 0)
        held.send()                         # only now may A's one create leave
    except BaseException:
        held.withdraw()
        raise
    finally:
        t.join(60)
    [number] = issues_with_marker(e)
    after = facts(gh, admin_conn, e, a)
    assert (after["intent"], after["execution"], after["creates"]) == ("succeeded", "reconciling", 1)
    gh.svc("admin", lambda s: s.reconcile(e["id"], resolution="adopt", rationale="the create landed",
                                          external_ref=f"{REPO}#{number}"))
    got = facts(gh, admin_conn, e, a)
    assert (got["execution"], got["external_ref"], got["reservation"], got["uses"]) == (
        "succeeded", f"{REPO}#{number}", "consumed", (1, 0))
    with pytest.raises(Conflict):
        gh.execute(p, a)


@only("normal")
def test_unavailable_credential_sends_nothing(gh, admin_conn):
    """Creates nothing; GitHub is not contacted. The connection's secret file does not exist."""
    from axiom.ingestion.sync import SyncService
    gh.connection = SyncService(gh.db, None, None).create_connection(
        gh.ctx_for("admin"), adapter="github_issues", scope_id=gh.world.a.project, display_name="missing secret",
        base_url=None, credential_ref=f"secretref:file{Path(TOKEN_FILE).parent / 'does-not-exist'}",
        config={"repo": REPO})
    p = gh.propose(gh.payload("no-credential"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    gh.make_worker("w").run_once(only_tenants={gh.world.a.id})
    got = facts(gh, admin_conn, e, a)
    assert (got["job"], got["intent"], got["reservation"]) == ("queued", "prepared", "reserved")
    assert gh.recorder.log == [], "a request was sent without a credential"
    assert "lookup failed" in (gh.job(e["job_id"])["last_error"] or "")


# ------------------------------------------------------------------------------------- refusal modes
@only("readonly")
def test_permission_refusal_creates_nothing_and_is_never_retried_as_a_create(gh, admin_conn):
    """Creates nothing (expected). The token was edited to Issues read-only: the lookup succeeds and the create is
    refused. The adapter treats 403 conservatively as an unknown outcome (GitHub uses 403 for rate limits too), so the
    job parks rather than creating again; the operator abandons and the use stays consumed. The refusal's status and
    accepted-permissions header are recorded for a later classification decision."""
    p = gh.propose(gh.payload("readonly"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    job = drive(gh, admin_conn, e)
    print(f"\nREFUSALS {gh.recorder.refusals}")
    got = facts(gh, admin_conn, e, a)
    assert gh.recorder.creates() == 1 and issues_with_marker(e) == []
    assert job["state"] == "needs_operator" and got["reservation"] == "reserved"
    gh.svc("admin", lambda s: s.reconcile(e["id"], resolution="abandon", rationale="create refused: read-only token"))
    got = facts(gh, admin_conn, e, a)
    assert (got["execution"], got["reservation"], got["uses"]) == ("failed", "consumed", (1, 0))


@only("revoked")
def test_revoked_token_is_refused_and_nothing_is_created(gh, admin_conn):
    """Creates nothing. Run after the token was deleted: GitHub refuses the lookup, so no create is attempted."""
    p = gh.propose(gh.payload("revoked"))
    a = gh.approve(p, max_uses=1)
    e = gh.execute(p, a)
    gh.make_worker("w").run_once(only_tenants={gh.world.a.id})
    print(f"\nREFUSALS {gh.recorder.refusals}")
    got = facts(gh, admin_conn, e, a)
    assert gh.recorder.creates() == 0 and [s for _, _, s in gh.recorder.log] == [401]
    assert (got["job"], got["reservation"]) == ("queued", "reserved")
