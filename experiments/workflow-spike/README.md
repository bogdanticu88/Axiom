# Workflow engine spike: Temporal

A bounded experiment to decide whether Temporal (Python SDK `temporalio`) meets the platform's
durable-workflow requirements for remediation actions: approval gating, recovery after worker and
server crashes, and safe handling of external effects whose acknowledgement was lost.
Findings and the recommendation are in [RESULTS.md](RESULTS.md).

Nothing here is wired into the platform. It is self-contained in this directory.

## Layout

| Path | What it is |
|------|------------|
| `spike/workflows.py` | `RemediationWorkflow`: persist proposal, durable approval wait (timer), digest and expiry checks, guarded effect, operator reconciliation |
| `spike/activities.py` | Activities. All side effects live here: platform DB writes and the external ticket call (intent, reconcile, create, result) |
| `spike/platform_db.py` | SQLite stand-in for the platform DB: `proposals`, `execution_intents`, `execution_results`, `workflow_events` |
| `spike/ticket_service.py` | Fake external ticket system, run as its own process (HTTP + SQLite). `--no-lookup` disables search by idempotency key |
| `spike/worker.py` | Worker process entry point |
| `tests/harness.py` | Starts real processes (Temporal dev server, ticket service, workers) and SIGKILLs them |
| `tests/test_scenarios.py` | The scenarios, with assertions |
| `tests/changed_workflows.py` | Changed workflow code used only for the replay (determinism) test |
| `scripts/fetch_temporal_cli.sh` | Downloads the official Temporal CLI (which contains the dev server) into `.bin/` |
| `results/pytest-final-run.log` | Verbatim output of the run quoted in RESULTS.md |

`.bin/`, `.venv/` and `.run/` (per-test logs and SQLite files) are git-ignored.

## Run from scratch

Requirements: Linux x86_64, `uv`, `curl`, network access to PyPI and temporal.download.

```bash
cd experiments/workflow-spike

# 1. Temporal CLI (contains `temporal server start-dev`). ~45 MB download, ~150 MB binary.
./scripts/fetch_temporal_cli.sh

# 2. Python environment from the committed lock (resolved with exclude-newer 2026-10-14).
uv sync --frozen

# 3. Run every scenario (about 80 s; real processes are started and SIGKILLed).
uv run --frozen pytest -v -s tests/
```

Run one scenario:

```bash
uv run --frozen pytest -v -s tests/test_scenarios.py::test_lost_ack_reconciles_by_lookup
```

To re-resolve dependencies (this changes `uv.lock`): `uv lock` (the `exclude-newer` cutoff is in
`pyproject.toml`).

Each test starts its own ticket service and workers on free ports and writes logs plus SQLite files
under `.run/<scenario>/`. One shared Temporal dev server (persistent SQLite file) serves most tests;
the server-restart test starts and SIGKILLs its own private server.

## Poking at it by hand

```bash
mkdir -p .run
.bin/temporal server start-dev --headless --port 7233 --db-filename .run/manual.db
uv run python -m spike.ticket_service --port 8099 --db .run/manual-tickets.db
uv run python -m spike.worker --address 127.0.0.1:7233 --task-queue manual
.bin/temporal workflow list --address 127.0.0.1:7233
```
