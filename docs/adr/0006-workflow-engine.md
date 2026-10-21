# ADR 0006: Durable workflow engine

Status: **pending** (2026-10-22). No engine is selected. This record will be completed when the like-for-like
comparison finishes.

## Requirements the engine must serve (unchanged by the choice)
Worker and server crashes; durable approval waits and timers; concurrent execution; leases, heartbeats and fencing of
stale workers; lost acknowledgements and uncertain external effects; bounded retries and reconciliation; cancellation
and permission revocation; tenant fairness and resource limits; workflow versioning during upgrades; backup
restoration and recovery; operational complexity. B07, B08, A02, A07, A08, A12, A15 apply whichever engine is chosen.

## Evidence so far
* `experiments/workflow-spike/` (Temporal Python SDK 1.34.0, CLI 1.9.1 / Server 1.32.0 dev server): 9 of 9 scenarios
  passed with real SIGKILLs of workers and the dev server, including approval waits, digest-mismatch rejection,
  expiry timers, lost-acknowledgement reconciliation, operator parking, and replay determinism checks. Independently
  re-run with the same result (9 passed in 76.11s).
* The experiment showed duplicate prevention for external effects depends on platform code (stable operation key,
  intent records, lookup before create). **That responsibility exists with either engine and is not an argument for
  either.**

## Work in progress
* `experiments/workflow-pg-spike/`: PostgreSQL-backed alternative (leases, fencing tokens, heartbeats, due-at timers,
  per-tenant limits) under the same crash suite plus stale-worker fencing, concurrency, revocation, retries, fairness,
  versioning and backup restore.
* Additional Temporal probes: minimal-identifier payloads and payload encryption, signal authorisation, tenant
  separation options, retention and deletion, heartbeat timeouts with stale workers, cancellation, workflow-ID
  deduplication, backup restore, versioning and operational footprint.

Neither experiment is a production engine.
