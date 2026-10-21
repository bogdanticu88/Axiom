# Workflow engine spike: PostgreSQL only

A bounded experiment, the counterpart of [`../workflow-spike`](../workflow-spike) (Temporal). It builds
the PostgreSQL-only alternative for single approved remediation actions (proposal, approval wait,
guarded external effect) and puts it through the same fault scenarios plus several the Temporal spike
did not run: stale-worker fencing, concurrency, revocation and cancellation, retries and dead letters,
tenant fairness, handler versioning, backup restore and a PostgreSQL server crash.

It is not a production engine. Nothing here is wired into the platform. Findings are in
[RESULTS.md](RESULTS.md).

## Layout

| Path | What it is |
|------|------------|
| `pgspike/schema.sql` | Tables: `workflow_runs`, `job_leases` (fencing token), `approvals`, `execution_intents`, `execution_results`, `run_events`, `tenant_limits`, `grants` |
| `pgspike/worker.py` | Worker process: claim (`FOR UPDATE SKIP LOCKED` + per-tenant limit), heartbeat, fencing gate, effect, result, reconciliation, retries/backoff, dead letter. Test hooks are listed in its docstring |
| `pgspike/api.py` | Platform side: create run, approve, revoke, cancel, operator resolve, post-restore runbook step, handler migration, drain status |
| `pgspike/ticket_service.py` | Fake external ticket system (same design as the Temporal spike's) with switches: `--no-lookup`, `--dedupe`, `--fencing`, `--fail-first N`, `--fail-after-create N`, `--delay-ms` |
| `tests/harness.py` | Real OS processes, signals, throwaway databases, private cluster for scenario 13, `pg_dump`/`pg_restore` |
| `tests/test_scenarios.py` | The scenarios (26 test cases) |
| `results/pytest-run.log` | Verbatim output of the final run quoted in RESULTS.md |

`.venv/` and `.run/` (per-test process logs and ticket SQLite files) are git-ignored.

## Requirements

* Linux, Python 3.13, `uv`.
* The disposable test cluster running: `scripts/dev/test-db.sh start` from the repo root. The tests
  read `.env.test` (admin DSN over the unix socket, host and port).
* PostgreSQL 16 binaries in `/usr/lib/postgresql/16/bin` (`pg_dump`, `pg_restore`, `initdb`, `pg_ctl`).
* Scenario 13 runs `initdb`/`pg_ctl` as the `postgres` OS user via `su`, so it needs root.

## Run

```bash
cd experiments/workflow-pg-spike
uv sync --frozen                                                   # from the committed uv.lock
uv run --frozen pytest -v -s tests/ 2>&1 | tee results/pytest-run.log   # about 100 s
```

One scenario, or everything except the private-cluster crash test:

```bash
uv run --frozen pytest -v -s tests/test_scenarios.py::test_06a_stale_worker_refused_at_gate
uv run --frozen pytest -v -s -k "not test_13" tests/
```

To re-resolve dependencies (changes `uv.lock`): `uv lock` (the `exclude-newer` cutoff is in
`pyproject.toml`).

## What the tests touch

* On the shared test cluster: one database `wfspike_<random hex>` per test (dropped afterwards; set
  `WFSPIKE_KEEP_DB=1` to keep it) and the login role `wfspike_worker` (NOSUPERUSER, DML only on schema
  `wf`, dropped at session end). Nothing else is created, altered or restarted there.
* Scenario 13 only: a private cluster in `/var/tmp/wfspike-pg` (socket dir `/var/tmp/wfspike-pg-sock`)
  on port 55499. It is SIGKILLed and restarted during the test and deleted afterwards, pass or fail.
* Ports for the fake ticket services are picked at random on 127.0.0.1.

## Poking at it by hand

```bash
uv run python -m pgspike.ticket_service --port 8099 --db .run/manual-tickets.db
WFSPIKE_DSN="host=127.0.0.1 port=55432 dbname=<db> user=wfspike_worker password=<pw>" \
  uv run python -m pgspike.worker --name w1 --ticket-url http://127.0.0.1:8099
```

Create a database and schema with `pgspike.api.install_schema(conn, "wfspike_worker")` first.
