# Workflow engine spike: results

Run date: 2026-10-21 (UTC), on a Linux x86_64 container, Python 3.13.16.
Everything below was executed; output is copied from `results/pytest-final-run.log` (the full,
unedited log of the final run). Long lines are shortened with `...` where marked.

## Resolved versions

| Component | Version | How it was obtained |
|-----------|---------|---------------------|
| `temporalio` (Python SDK) | **1.34.0** | `uv lock` with `exclude-newer = 2026-10-14T00:00:00Z` (see `uv.lock`) |
| Other locked deps | nexus-rpc 1.4.0, protobuf 7.36.2, types-protobuf 7.35.1.20260906, typing-extensions 4.16.0, pytest 9.1.1, pluggy 1.6.0, iniconfig 2.3.1, packaging 26.3, pygments 2.21.0 | same lock |
| Temporal CLI / dev server | `temporal version 1.9.1 (Server 1.32.0, UI 2.54.1)` | `https://temporal.download/cli/archive/latest?platform=linux&arch=amd64`, served as `temporal_cli_1.9.1_linux_amd64.tar.gz` (Last-Modified 2026-09-14) |
| CLI tarball sha256 | `09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5` | computed locally; **not verified against a published checksum** (the GitHub release checksum URL returned 404 from this network, so there was nothing to compare with) |

Note: "latest" from temporal.download is not pinned. A rerun on another day may fetch a newer CLI.
For a real adoption the server image version must be pinned explicitly.

## Commands run

```bash
cd experiments/workflow-spike
./scripts/fetch_temporal_cli.sh          # sha256 + tar listing (LICENSE, temporal) + `temporal --version`
uv lock && uv sync                       # resolved temporalio==1.34.0
uv run --frozen pytest -v -s tests/      # final run, log in results/pytest-final-run.log
```

The full suite was run five times (plus single-test runs while developing). Run 1 (7 tests at the
time) had 6 passed, 1 failed, because of a harness bug (`asyncio.run()` called from inside a running
loop when restarting the server). Run 2 (8 tests) had 7 passed, 1 failed, because of a test bug
(`WorkflowHandle.result()` does not take `result_type`; it belongs on `get_workflow_handle`).
Neither failure was a Temporal behaviour. The failed runs leaked two child processes (fixed since:
the harness now reaps every process it started, pass or fail). Runs 3, 4 and 5 each passed 9/9 with
the same timings (10.1 s, 3.1 s, 15.7 s, 10.0 s). Run 5 is the one quoted here.

```
========================= 9 passed in 75.86s (0:01:15) =========================
```

## Scenarios and observed results

All processes are real OS processes. "SIGKILL" means `os.killpg(pid, SIGKILL)`; the worker gets no
chance to shut down or report anything to the server.

| # | Scenario | Test | Result |
|---|----------|------|--------|
| 1 | Approval wait, then valid approval executes once | `test_worker_sigkill_while_awaiting_approval` | PASS |
| 1a | Approval for a different payload digest (argument substitution) is refused, recorded as `approval_mismatch`, no effect | `test_approval_digest_mismatch_does_not_execute` | PASS |
| 1b | Expired approval is not used | `test_expired_approval_is_not_used` | PASS |
| 1c | Approval deadline is a durable workflow timer | `test_approval_deadline_timer` | PASS |
| 2 | Worker SIGKILLed while waiting for approval, new worker, approval, exactly one ticket | `test_worker_sigkill_while_awaiting_approval` | PASS |
| 3 | Lost acknowledgement: ticket created, worker SIGKILLed before the activity returns, retry reconciles by lookup and adopts | `test_lost_ack_reconciles_by_lookup` | PASS |
| 3-ctl | Negative control: same crash with the lookup disabled produces a duplicate | `test_negative_control_naive_retry_duplicates` | PASS (2 tickets, as expected) |
| 3b | Lost acknowledgement, external system cannot search: workflow parks in `needs_operator_reconciliation` until an operator signal | `test_lost_ack_without_lookup_needs_operator` | PASS |
| 4 | Intent recorded before effect, result appended after | asserted inside 3 and 3b | PASS |
| 5 | Temporal dev server SIGKILLed and restarted (same `--db-filename`) mid-wait | `test_server_sigkill_restart_while_awaiting_approval` | PASS |
| 6 | Determinism: replay a real history against changed code, with and without `workflow.patched` | `test_replay_detects_unpatched_change` | PASS |

### 1 and 2. Approval wait across a worker SIGKILL

The workflow persists the canonical proposal (sorted-key compact JSON) and its sha256 through an
activity, then blocks in `workflow.wait_condition(..., timeout=approval_window)`. Worker-1 is killed
while it waits, worker-2 starts, the approval signal is sent.

```
[00:21:12] workflow is awaiting approval; SIGKILL worker-1
[00:21:12] SIGKILLed worker-1 pid=2358 rc=-9
[00:21:14] started worker-2 pid=2367
[00:21:24] result after 10.1s: WorkflowOutcome(status='completed', payload_digest='33983f26...', operation_key='97d30471...', ticket_id='TCK-d5b9c1ee', detail='created', ...)
[00:21:24] external tickets: [{'id': 'TCK-d5b9c1ee', 'idempotency_key': '97d30471efa03b07...', ...}]
[00:21:24] platform_db.execution_intents: 1 row(s)
[00:21:24]     {"id": 1, "operation_key": "97d30471efa03b07...", ..., "attempt": 1, "recorded_at": "2026-10-21T21:21:24.550055+00:00"}
[00:21:24] platform_db.execution_results: 1 row(s)
[00:21:24]     {"id": 1, "operation_key": "97d30471efa03b07...", "outcome": "created", "ticket_id": "TCK-d5b9c1ee", "attempt": 1, ...}
PASSED
```

The 10.1 s between signal and completion is explained by the recorded history, which contains
`workflow_execution_signaled, workflow_task_scheduled, workflow_task_timed_out, workflow_task_scheduled, ...`.
The server first dispatched the workflow task to the dead worker's sticky queue and only moved it
to the normal queue after the sticky schedule-to-start timeout (SDK default 10 s,
`Worker(sticky_queue_schedule_to_start_timeout=...)`). Correct, but it is a latency cost after any
hard worker crash.

### 1a. Digest mismatch (argument substitution)

The approval carried the digest of `{**PROPOSAL, "asset": "*"}`.

```
[00:21:25] result: WorkflowOutcome(status='approval_mismatch', ..., detail='approved digest ad0bfd964f6d1546 != proposal digest 33983f26b3ad5a73', ...)
[00:21:25] platform_db.execution_intents: 0 row(s)
[00:21:25] platform_db.execution_results: 0 row(s)
[00:21:25] platform_db.workflow_events: 1 row(s)
[00:21:25]     {"id": 1, "workflow_id": "remediation-a4258006", "event": "approval_mismatch", ...}
PASSED
```

Asserted: zero tickets in the external system, zero intents. Design choice in this spike: a
mismatch closes the workflow (fail closed) instead of waiting for another approval.

### 1b. Expired approval

The approval's `expires_at` was 5 s in the past. The workflow compares it to `workflow.now()`
(deterministic workflow time) immediately before execution.

```
[00:21:26] result: WorkflowOutcome(status='approval_expired', ..., detail='approval expired at 2026-10-21T21:21:21.302576+00:00', ...)
PASSED
```

Not tested: an approval that is valid when received and expires while an earlier step is still
running. The same check would catch it because it runs at use time, but no test exercises that timing.

### 1c. Approval deadline timer

With `approval_window_seconds=3` and no approval:

```
[00:21:29] result after 3.1s: WorkflowOutcome(status='approval_deadline_exceeded', ...)
[00:21:29] late approval signal -> RPCError: workflow execution already completed
[00:21:29] timer events: ['timer_started_event_attributes', 'timer_fired_event_attributes']
PASSED
```

The deadline is a server-side timer (`TimerStarted`/`TimerFired` in history), and a late approval
is rejected by the server because the execution is closed.

### 3 and 4. Lost acknowledgement with reconciliation, intent before effect

The activity: (a) counts unresolved intents for the operation key, (b) inserts an intent row,
(c) looks up the external system by idempotency key, (d) creates if nothing found, (e) appends a
result row. The operation key is `sha256(workflow_id + ":" + proposal_digest)`, so it is the same on
every retry and replay. A test hook makes attempt 1 hang after the ticket is created; the test
waits for that and SIGKILLs the worker. The fake ticket service deliberately does **not**
deduplicate on the key, so only the reconcile step can prevent a duplicate.

```
[00:21:30] ticket exists, activity has not returned; SIGKILL worker-1
[00:21:30] SIGKILLed worker-1 pid=2417 rc=-9
[00:21:30] started worker-2 pid=2429
[00:21:46] result 15.7s after restart: WorkflowOutcome(status='completed', ..., ticket_id='TCK-1b639555', detail='adopted', ...)
[00:21:46] external tickets: [{'id': 'TCK-1b639555', 'idempotency_key': '7cd84efdbc851ffcd323333433ff5375f3fa3709774201316544bb00c95778ea', ...}]
[00:21:46] platform_db.execution_intents: 2 row(s)
[00:21:46]     {"id": 1, "operation_key": "7cd84efdbc851ffc...", ..., "attempt": 1, "recorded_at": "2026-10-21T21:21:30.739115+00:00"}
[00:21:46]     {"id": 2, "operation_key": "7cd84efdbc851ffc...", ..., "attempt": 2, "recorded_at": "2026-10-21T21:21:36.749544+00:00"}
[00:21:46] platform_db.execution_results: 1 row(s)
[00:21:46]     {"id": 1, "operation_key": "7cd84efdbc851ffc...", "outcome": "adopted", "ticket_id": "TCK-1b639555", "attempt": 2, ...}
PASSED
```

Asserted: one ticket, its id equals the workflow result, intents for attempts [1, 2], exactly one
result `("adopted", 2)`, and no result row existed right after the kill (outcome unknown).
Timing: attempt 2 started 6 s after attempt 1, which is `start_to_close_timeout=5s` plus the 1 s
retry backoff. Temporal only learns a worker died through that timeout (or a heartbeat timeout, not
used here). The remaining ~10 s is the sticky-queue timeout described above.

Negative control, same crash with the lookup disabled:

```
[00:22:03] result: status=completed detail=created; external ticket count=2: ['TCK-3cce48ee', 'TCK-6ee6ed73']
PASSED
```

This is the key evidence for what Temporal does and does not do. Temporal retried the activity
correctly; it did not and cannot prevent the second external effect. The reconcile step written in
the activity is what made the difference.

### 3b. Lost acknowledgement, no lookup available

Ticket service started with `--no-lookup` (search returns HTTP 501). Attempt 2 sees an unresolved
intent from attempt 1 and cannot search, so it raises a non-retryable `ApplicationError` of type
`UncertainEffect`. The workflow catches it, moves to `needs_operator_reconciliation` and waits on a
signal with no timeout.

```
[00:22:15] workflow reached needs_operator_reconciliation after 10.0s
[00:22:20] after 5s parked: tickets=1, status still needs_operator_reconciliation
[00:22:20] result: WorkflowOutcome(status='completed', ..., ticket_id='TCK-500147a3', detail='operator_adopted', ...)
[00:22:20] platform_db.execution_intents: 2 row(s)
[00:22:20] platform_db.execution_results: 1 row(s)
[00:22:20]     {"id": 1, "operation_key": "f09cf4ba97ee0881...", "outcome": "operator_adopted", "ticket_id": "TCK-500147a3", "attempt": 1, ...}
[00:22:20] platform_db.workflow_events: 2 row(s)
[00:22:20]     {"id": 1, ..., "event": "needs_operator_reconciliation", "detail": "1 earlier attemp...", ...}
[00:22:20]     {"id": 2, ..., "event": "completed", "detail": "operator bob adopted TCK-500147a3", ...}
PASSED
```

Asserted: one ticket before and after the operator decision, status unchanged after 5 s parked.
(The `attempt` value on the operator row is the attempt number of the recording activity, not of
the effect.) Not tested: the operator "abandon" branch, and an operator decision that the earlier
attempt did not create anything.

### 5. Temporal server SIGKILL and restart mid-wait

A private dev server with `--db-filename .run/server-restart/temporal.db`; server and worker-1
SIGKILLed while the workflow waits; server restarted on the same port and file; worker-2 started.

```
[00:22:22] SIGKILLed temporal-server:45861 pid=2495 rc=-9
[00:22:22] SIGKILLed worker-1 pid=2505 rc=-9
[00:22:22] started temporal-server:45861 pid=2513
[00:22:22] temporal server ready at 127.0.0.1:45861
[00:22:22] started worker-2 pid=2521
[00:22:22] after server restart: workflow remediation-9567f50d status=RUNNING
[00:22:23] result: WorkflowOutcome(status='completed', ..., ticket_id='TCK-a2f6c6d4', detail='created', ...)
[00:22:23] external ticket count=1
PASSED
```

This proves durability of the single-process dev server with SQLite only. It says nothing about a
production cluster (separate frontend, history, matching and worker services on PostgreSQL or
another supported store), which was not tested.

### 6. Determinism and versioning

A real 29-event history was replayed with `temporalio.worker.Replayer` against three versions of
the code: the original, a version that adds a `workflow.sleep` before the first activity, and the
same change guarded by `workflow.patched("cool-down-step")`.

```
[00:22:25] replay with original: OK
[00:22:25] replay with unpatched_change: NondeterminismError: ... [TMPRL1100] Nondeterminism error: Timer machine does not handle this event: HistoryEvent(id: 5, ActivityTaskScheduled
[00:22:25] replay with patched_change: OK
PASSED
```

This is the operational cost of Temporal in concrete form: any change to the order of commands in
a workflow with open executions must be patched (or shipped as a new workflow type or under Worker
Versioning), and replay tests against captured histories belong in CI.

## What Temporal did and did not guarantee here

It did:

* keep the approval wait, its deadline timer and the received signal durable across a worker
  SIGKILL and a server SIGKILL (dev server, SQLite);
* retry a crashed activity, with the attempt number available to the activity, and stop retrying on
  a non-retryable error type;
* reject a signal to a closed workflow;
* detect an incompatible code change on replay.

It did not, and does not claim to:

* provide exactly-once external effects. Temporal's docs state that "Activities follow an
  at-least-once execution model" and recommend idempotency keys
  (https://docs.temporal.io/develop/python/failure-detection). The negative control shows a
  duplicate ticket with correct Temporal behaviour. Duplicate prevention came entirely from the
  intent/reconcile code and from the external system offering a lookup;
* notice a dead worker quickly. Detection is bounded by `start_to_close_timeout` (or a heartbeat
  timeout), and workflow tasks pay the sticky-queue timeout (10 s default) after a hard crash;
* authenticate approvals. A signal is accepted from any client with access to the namespace, and
  the approver field in this spike is self-asserted. In the platform the approval must be decided
  and recorded by the API (RBAC, separation of duties, audit in PostgreSQL), and the workflow
  should only receive a reference that an activity verifies against the platform DB.

## Limitations and costs observed or checked

* **Determinism constraints.** Workflow code runs in a sandbox with a custom event loop; wall
  clock, randomness, I/O and most of the standard library are restricted (the default
  `SandboxRestrictions` list is long). All DB and HTTP access had to go through activities, and
  modules had to be imported via `workflow.unsafe.imports_passed_through()`. This is manageable but
  is a second programming model for the team.
* **Versioning for long-lived workflows.** Approval waits can last days. Per the Python versioning
  docs (https://docs.temporal.io/develop/python/versioning) changes need `workflow.patched` /
  `deprecate_patch`, Worker Versioning, or a new workflow type; the legacy Worker Versioning API is
  marked deprecated. Demonstrated in scenario 6.
* **History size.** Documented limits are 51,200 events or 50 MB per execution, warnings at 10,240
  events or 10 MB (https://docs.temporal.io/workflow-execution/limits). Not a concern for one
  remediation action (29 events here); it matters if a workflow loops over many findings, which
  then needs Continue-As-New or child workflows. Not tested.
* **Data in Temporal's store.** The proposal payload, approval and results are stored in Temporal
  history, outside PostgreSQL row-level security and the platform's tenancy model. Tenant isolation
  would need namespaces or a payload codec (encryption), and retention must match the platform's
  evidence and deletion rules. Not tested.
* **Operational burden.** The dev server used here is explicitly "not intended for production use"
  (CLI help text). A self-hosted Temporal Service needs a persistence database (Cassandra, MySQL or
  PostgreSQL per the docs), typically a visibility store (the official Compose example adds
  Elasticsearch), the server services as separate pods under Helm, and the docs say it "should be
  secured similarly to a database" (https://docs.temporal.io/self-hosted-guide/deployment). They also
  note Helm chart versions below 0.73.1 are incompatible with server images 1.30 and later. That is
  one more stateful system to upgrade, back up, monitor and secure in Compose and Helm. Not built here.
* **Binary size.** The CLI with embedded dev server is about 150 MB; fine for development.
* **Licence.** MIT for all three pieces checked: the CLI tarball's `LICENSE` ("The MIT License,
  Copyright (c) 2024 Temporal Technologies Inc."), the Python SDK wheel
  (`License-Expression: MIT`, `temporalio-1.34.0.dist-info/licenses/LICENSE`), and the server repo
  `https://raw.githubusercontent.com/temporalio/temporal/v1.32.0/LICENSE` (HTTP 200; main branch reads
  "The MIT License, Copyright (c) 2025 Temporal Technologies Inc. ... Copyright (c) 2020 Uber
  Technologies, Inc."). Licences of transitive server dependencies and the Web UI were not reviewed.

## Not tested

* A production-shaped Temporal cluster (PostgreSQL persistence, multiple services, upgrades,
  backup and restore, failover).
* Load, throughput, latency under contention, history growth.
* Heartbeating long-running activities; activity cancellation.
* Worker Versioning (only `workflow.patched` was exercised).
* Payload codec / encryption, namespaces per tenant, mTLS, authorisation of signals.
* Operator "abandon" path; approval expiring between receipt and use.
* Crash between the intent write and the external call (lookup would find nothing and create;
  the code path is the normal one, but no test forces that window).
* Any PostgreSQL-only implementation. The comparison below is qualitative.

## Comparison with a PostgreSQL-only alternative (qualitative, not built)

The PostgreSQL-only design: the remediation action is a row with a state machine; approvals are
rows written by the API in the same transaction as audit and outbox entries (the repo already has
`axiom.outbox` with immutability triggers in `backend/migrations/0001_foundation.sql`); a job table
claimed with `SELECT ... FOR UPDATE SKIP LOCKED` and a lease expiry; durable timers as `due_at`
columns polled by a sweeper.

What carries over unchanged: everything that actually prevented duplicates and unauthorised
execution in this spike lives outside Temporal. The stable operation key, intent-before-effect
rows, reconcile-by-lookup, the `needs_operator_reconciliation` state, digest binding and expiry
checks are all plain code plus tables, and would be identical in a PostgreSQL-only design.

What PostgreSQL-only does better for this platform:

* Approval, audit, decision and the "may execute" check can be one transaction under the
  existing RLS and tenancy model. With Temporal the approval exists in two stores and must be
  reconciled between them.
* No second stateful system to deploy, secure, back up and upgrade, and no determinism or
  workflow-versioning discipline. A schema migration is the only versioning concern.
* The implementation plan already says to "avoid adding a second task queue unless a demonstrated
  requirement justifies it".

What Temporal does better:

* Timers, retries with backoff, signal delivery, crash recovery and replay come built in and were
  shown to work under SIGKILL in a few hundred lines. In PostgreSQL these are hand-built: lease
  expiry and stealing, poison-job handling, backoff, timer sweeps, and ordering of signals versus
  timers. Each is simple; the combination is where bugs hide, and it needs its own fault-injection
  tests (acceptance criterion A12 applies either way).
* Multi-step orchestration (fan-out over many findings, compensation, child workflows) and an
  inspectable history and UI for each execution.
* Detection latency is tunable but similar in kind: both depend on a lease or timeout to notice a
  dead worker. No measurements of a PostgreSQL implementation exist, so no speed comparison is made.

## Recommendation: undecided, leaning PostgreSQL-only for remediation actions

Temporal met every functional requirement exercised here. Approval waits, deadline timers and
signals survived real worker and server SIGKILLs, retries behaved as documented, and
non-deterministic changes were caught on replay. Nothing failed for Temporal-related reasons.

The spike does not show that Temporal is needed for this workflow. The safety properties that
matter most (no duplicate ticket after a lost acknowledgement, no execution on a substituted or
expired approval, operator parking when the outcome is unknowable) came from platform code that a
PostgreSQL-only design needs anyway. Temporal adds durable timing and retry plumbing on top of
that, at the price of a second stateful system holding tenant data outside RLS, a determinism and
versioning discipline for days-long waits, and approvals living in two stores.

Suggested next step before deciding: build the same scenarios on PostgreSQL only (job table with
leases, `due_at` timers, the existing outbox), run this same fault-injection suite against it, and
compare the amount and complexity of code. Adopt Temporal if the platform's roadmap actually needs
multi-step, long-running orchestration beyond single approved actions; otherwise PostgreSQL-only is
the smaller, more governable choice.
