# Contributing

This repository implements the evidence-backed vulnerability management platform specified in
`docs/Axiom-*.md`. Those three documents are the design inputs; the agreed scope is the complete
platform, delivered in phases A to F. Do not reduce scope silently: propose changes in `docs/DECISIONS.md`.

## Before you start
1. Read `docs/HANDOFF.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/REQUIREMENTS.md`, `docs/DECISIONS.md` and the ADRs.
2. Inspect `git status` and `git log`. Resume from the actual state; do not assume unfinished items are done.
3. Start the disposable database: `scripts/dev/test-db.sh start`, then `uv sync --frozen` and `uv run pytest tests -q`.

## Rules
* **Tenant boundaries are non-negotiable.** Every tenant-owned table needs `tenant_id`, composite keys and FKs, forced
  RLS via `axiom.apply_tenant_policy`, and explicit column grants. Never use session-level `set_config` for context; use
  `Database.tenant_tx`. Never trust tenant, actor, authority or "verified" flags from request bodies.
* **No generic state changes.** Case and evidence state changes go through domain commands that write audit, event and
  outbox rows in the same transaction. Do not add UPDATE grants that bypass them.
* **Migrations are forward-only.** Never edit an applied migration (the runner rejects checksum changes); add
  `NNNN_name.sql` under `backend/axiom/migrations/`.
* **Statuses must be honest.** Mark a requirement `verified` only when a test you ran exercises it, and record the
  command and result in `docs/VERIFICATION.md`. Never invent logs, metrics or vendor API fields.
* **Connectors**: support levels are planned / fixture-tested / sandbox-validated / production-supported. Fixtures
  must be synthetic or redacted with origin and licence noted. Never claim live support from fixtures.
* **No external effects without authorisation**: do not push, publish, deploy publicly, spend money, contact people
  or use corporate systems or credentials. Production mutation stays disabled.
* **Dependencies**: pin and lock (`uv lock` honours `exclude-newer`); pin images by digest; check official docs for
  current APIs before using them.
* **Secrets**: never commit `.env`, `.env.test`, generated keys, database data or real evidence.
* Use the Python package name `axiom` (ADR 0001).

## Before you finish
Update `docs/IMPLEMENTATION_STATUS.md`, `docs/REQUIREMENTS.md`, `docs/VERIFICATION.md` (exact commands and results)
and `docs/HANDOFF.md` (next tasks, commands, commit ID). Leave the tree reproducible.
