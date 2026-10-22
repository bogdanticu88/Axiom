# ADR 0010: External action protocol, duplicate prevention and restore detection

Status: accepted (2026-10-22). Builds on ADR 0006 (PostgreSQL-backed job runner).

## Context
Specification S 9 and Implementation Plan S 7 require actions to be proposed canonically, approved for an exact
version, re-checked immediately before the effect, executed with durable intent and provider idempotency where
available, and reconciled when the outcome is unknown, without promising exactly-once execution. Two observations
from review shaped this ADR:

* **Lookup before create does not by itself prevent duplicates.** A lookup can miss an object that exists: search
  indexes lag, and a stale worker may still be about to send its request. Atlassian's "search and reconcile" guidance
  states the Jira Cloud JQL search API does not provide read-after-write consistency by default; `reconcileIssues`
  only helps for issue IDs the caller already knows, which is exactly what a lost acknowledgement does not provide.
* **Discarding a stale worker's result does not undo its effect.** Once a request is on the wire, fencing the
  worker's *database* writes cannot stop the *external* effect.

## Decision
### Data model (migration 0005)
| Table | Contract |
|---|---|
| `action_proposals` | Stable identity, status, current version. Identity immutable; versions advance one at a time. |
| `action_proposal_versions` | Immutable. The **database** computes `payload_digest` = SHA-256 over the canonical jsonb of tenant, proposal, version, effect class, scope, case, connection, resources, payload, preconditions and expiry. |
| `approvals` | Bound to one version **and its digest** through a composite foreign key `(version_id, payload_digest)`. Only the current version of an open proposal can be decided. Approver cannot be any author of the proposal (service and trigger). `valid_until` cannot exceed the version expiry. `max_uses`; counters `uses_reserved` and `uses_released` only move forward by one; CHECK `uses_reserved - uses_released <= max_uses`. Binding columns are immutable; revocation is terminal. |
| `approval_reservations` | One row per reserved use, `use_number` must equal the counter set in the same transaction; unique per approval and use number. A use is **released only if the effect was never attempted** (the trigger checks the effect intent is absent or still `prepared`): timeouts never return a use. |
| `action_executions` | One per reservation, stable `external_operation_id` = SHA-256(tenant, execution). Created only against an active approval of the exact version and digest. Guarded state machine prepared / executing / reconciling / succeeded / failed / cancelled. |
| `external_references` | Append-only, unique per execution and per (provider, connection, external id); records whether the reference was verified and how it was obtained (created, adopted by lookup, adopted by operator). |
| `idempotency_keys` | (tenant, principal, endpoint, key) with request digest over path parameters and body, and the stored response (API-07). |

Effect classes are distinct (ACT-08): `ticket.create` (enabled; Jira-style, fixture-tested), `pull_request.create`
(planned, disabled), `production.change` (disabled by default, no executor).

### Pre-execution re-check (ACT-03, A07, A08, ACT-10)
Inside the effect gate's fenced transaction, immediately before marking the intent executing (and again before the
lookup): proposal open and the approved version still current; digests match; version and approval unexpired;
approval active; the **approver still holds** `action.approve` for the scope (role bindings, membership status and
validity are re-read); the **requester still holds** `action.execute`; preconditions hold (case not closed, case
priority unchanged, scope unchanged); the connection is active.

### Reservation under concurrency (ACT-07)
`request_execution` locks the proposal row, then the approval row (always that order), re-checks validity, then
increments `uses_reserved`, inserts the execution and the reservation, and enqueues the job, all in one transaction.

### Effect gate decision rules
Each integration declares capabilities: `dedupe` (`idempotency_key`, `unique_external_id`, `none`), `lookup`
(`strong`, `eventual`, `none`) and `provider_fencing`. A repeated create is **safe** only with `dedupe != none` or
provider fencing.

| Intent state at the gate | Lookup hit | Lookup miss or no lookup |
|---|---|---|
| `prepared` (never attempted), database not restored | adopt | create (first attempt) |
| `executing` / `unknown` (an attempt may have reached the provider), or database restored | adopt | **create again only if repeat-safe; otherwise park for an operator** |

The transition to `executing` re-reads the intent under a row lock, so two jobs that raced on the same operation key
cannot both send a first attempt (the loser parks). A Jira-style connection declares `dedupe=none`, `lookup=eventual`,
no fencing, so after an uncertain create it adopts a hit and otherwise parks. It never re-creates.

### Guarantees and limits
* **At most one first attempt per operation key**, and never an automatic repeat to a provider that cannot deduplicate
  or fence. Tested: race of two jobs on one key; lost acknowledgement with a lagging index; stale worker already past
  the boundary; 4 workers by 12 executions.
* **A stale worker that already passed the boundary can still deliver its request.** Only provider deduplication or
  fencing stops the resulting duplicate (tested: idempotency key, unique external id and fencing variants each end
  with one ticket; the Jira-style variant parks the new worker and ends with exactly the stale worker's ticket).
  The platform does not claim to prevent that duplicate for providers without those features; it detects the
  uncertainty and requires reconciliation.
* **Capability declarations must be true.** Declaring idempotency for a provider that does not honour it produces
  duplicates (tested as a control). The jira_style adapter never declares deduplication.
* Outcome classification for the Jira-style adapter: connection errors before a connection exists are "definitely
  not applied" (safe retry); 400/401/403/404 are permanent; **429 and 5xx are treated as unknown** because no
  documented guarantee says the request was not processed (conservative; revisit with sandbox validation).
* Operator reconciliation (`action.reconcile`, privileged, audited) can adopt an external reference, declare the
  effect not applied (re-runs the *same* reserved use through the full re-check) or abandon. It never creates,
  extends or re-mints approval; an abandoned execution keeps its use consumed.

### Restore detection
**Mechanism 1: fingerprint (ADR 0006).** `system_identifier:timeline:database OID`. Detects a restore into a different
cluster, a new timeline or a new database. Workers refuse to run until an operator acknowledges the new fingerprint;
jobs and intents carried across the restore park when the integration cannot deduplicate.

**Blind spot of mechanism 1 (tested).** A rollback that keeps all three values is invisible: a storage snapshot of the
same data directory (`tests/drills/test_physical_snapshot.py`, real stop / copy / restore of a cluster) and a logical
restore into a database recreated with the same OID (`test_restore_witness.py`). The acknowledgement table is
restored with the database, so a marker kept in the database cannot reveal its own rollback.

**Mechanism 2: external witness.** The gate draws a watermark from `axiom.effect_watermark_seq` in the transaction that
marks an intent executing and records it in a witness **outside the database before the request is sent** (if the
witness write fails, the transaction rolls back and nothing is sent). Sequences are not rolled back with failed
transactions, so normally the database value is at or above the witness. A database whose watermark is below the
witness was rolled back after effects were recorded: workers refuse to run and gates park. An empty witness while
the database has issued watermarks is also refused (lost witness). Acknowledgement moves the sequence past the
witness. Backends: a directory (per-worker files, fsync and atomic rename) or an S3 prefix (per-worker objects).
Each worker writes only its own record, upwards only.

**Blind spots of mechanism 2 (tested or stated).**
* Witness restored together with the database: the rollback is invisible (tested; duplicate occurs). The witness
  must be in a different backup domain (different volume, bucket or account, not part of the same snapshot policy).
* A rollback that loses no effects (no attempt after the backup point) is not flagged, and needs no reconciliation.
* Effects attempted without the witness configured are not covered. The worker refuses to start in production without
  `AXIOM_RESTORE_WITNESS` (implemented in `workers/jobs.build_witness`; that refusal itself is not tested).
* S3 witness: not exercised against SeaweedFS or any S3 service yet (the directory backend is tested).

### Support levels
The Jira-style integration is **fixture-tested** against a local fake whose request and response shapes follow
Atlassian's public REST v3 documentation. It has not been run against a Jira site. This is not Jira support.

## Consequences
Parks are more frequent than with a naive lookup-then-create policy (every uncertain Jira-style create needs an
operator unless the index has caught up). That is the price of not creating duplicates. A provider with
idempotency keys, unique external identifiers or fencing removes most parks.

## Not tested
Live Jira or any live tracker; S3 witness backend; witness in a separate account; point-in-time recovery (archive
recovery creates a new timeline per PostgreSQL documentation, so the fingerprint should change, but this was not run);
load beyond 4 workers by 12 executions.
