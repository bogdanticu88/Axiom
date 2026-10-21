# ADR 0001: Repository layout and Python package name

Status: accepted (2026-10-22)

## Context
The implementation plan (section 2) proposes `backend/platform/{api,domains,...}`. A top-level Python package named
`platform` shadows the standard-library `platform` module, which uvicorn, cryptography tooling and others import.
That breaks in subtle, import-order-dependent ways.

## Decision
* The backend package is `axiom`, rooted at `backend/axiom/`.
* Layout mirrors the plan's intent: `api/`, `auth/`, `domains/<area>/`, `migrations/` (shipped inside the package so
  installed images carry them), `access.py`, `audit.py`, `outbox.py`, `db.py`.
* Adapters, workflows, tools and the model gateway get `backend/axiom/{adapters,workflows,tools,model_gateway}`
  as they are built. The web app goes to `apps/web`. Deployments in `deployments/{compose,helm}`.
* Supplied scaffolding is kept for reference in `docs/design-inputs/original-foundation/`.

## Consequences
Paths in the plan are read with `platform` replaced by `axiom`. No functional change to the design.
