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

Effect classes are distinct (ACT-08): `ticket.create` (enabled; Jira-style, ServiceNow and GitHub Issues adapters, all
fixture-tested), `pull_request.create` (planned, disabled), `production.change` (disabled by default, no executor).
Each class has its own `action.propose:<class>`, `action.approve:<class>` and `action.execute:<class>` permission
(migration 0009). Checks match the exact class with no hierarchy, so a permission for a weaker class never authorises
a stronger one, and the generic `action.*` permissions are no longer granted or checked.

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

**Acknowledging a restore does not authorise replay (migration 0010).** Acknowledgements are an append-only log. Any
job created before the latest acknowledgement counts as carried across a restore: for integrations that cannot
deduplicate, its effect parks until an operator reconciles **that job** (adopt, not applied, or abandon), which sets
`recovery_cleared_at`. Acknowledging, retrying or re-running never clears it (`rw::test_acknowledging_a_restore_does_
not_authorise_replay`). Jobs created after the acknowledgement run normally.

**Mechanism 2: external witness.** The gate draws a watermark from `axiom.effect_watermark_seq` in the transaction that
marks an intent executing and records it in a witness **outside the database before the request is sent** (if the
witness write fails, the transaction rolls back and nothing is sent). Sequences are not rolled back with failed
transactions, so normally the database value is at or above the witness. A database whose watermark is below the
witness was rolled back after effects were recorded: workers refuse to run and gates park. An empty witness while
the database has issued watermarks is also refused (lost witness). Acknowledgement moves the sequence past the
witness. Records are **write-once**: one file or object per watermark, named `<watermark:020d>-<worker>`; the high-water mark
is the largest name in a listing. Concurrent writers, duplicate worker IDs and retried writes after a lost
acknowledgement can therefore never lower it (an earlier per-worker overwrite design could, if two instances shared a
worker ID). Older records are pruned as described in "Witness pruning" below. Backends: a directory (fsync and atomic rename) or an S3
prefix. An unreadable witness makes effects retry later (nothing is sent); a failed write rolls back the transaction
that would have marked the intent executing, so nothing is sent. Workers refuse to start when the witness is missing
in production, malformed, or fails a write/list/delete probe (`unit::test_witness_config`).

**Storage assumptions that need independent validation for each production store.** The tests use SeaweedFS 4.48
and a local directory only (`s3w::*`: write-once records and pruning, 8 concurrent writers including two with the
same worker ID with a monotonic high-water mark observed between listings, unavailable endpoint, lost acknowledgement,
read-only and no-list identities). For a production store the following must be shown, not assumed:
* durability of an acknowledged PUT;
* a listing issued after a successful PUT returns that object (read-after-write list consistency);
* the witness bucket or account is not restored or rolled back with the database (no shared snapshot policy; object
  versioning or lock must not be used to roll it back);
* the worker identity can write, list and delete only under its prefix, and nothing else can delete there (deletion
  of the newest records would hide a rollback);
* availability: an outage pauses all external effects (fail closed).

**Blind spots of mechanism 2 (tested or stated).**
* Witness restored together with the database: the rollback is invisible (tested; duplicate occurs). The witness
  must be in a different backup domain (different volume, bucket or account, not part of the same snapshot policy).
* A rollback that loses no effects (no attempt after the backup point) is not flagged, and needs no reconciliation.
* Effects attempted without the witness configured are not covered. The worker refuses to start in production without
  `AXIOM_RESTORE_WITNESS` (`workers/jobs.build_witness`; `unit::test_witness_config::test_production_without_witness_refuses`).
* S3 witness: exercised against SeaweedFS only; see "Storage assumptions" above for what a production store must prove.

### Witness pruning (audited 2026-10-22)
**Who may delete.** Only a worker process, through its own witness client, and only records whose owner part of the
name (`name[21:]`, after `<20 digits>-`) is *exactly* its own sanitised worker ID. The earlier implementation matched
by suffix (`endswith("-w1")`), so worker `w1` could prune worker `a-w1`'s records; that is fixed and tested. Nothing
else in the platform deletes witness records. Operators and storage administrators must not; the storage identity
should allow delete only to the workers' identities (see "Storage assumptions").

**What may be deleted.** Only records named in the listing the worker has just read, and only those ranked below the
newest `KEEP` (3) of that worker's own records in that listing (`witness.prune_candidates`). A `KEEP` below 1 deletes
nothing.

**Invariant.** Every deleted record had at least `KEEP` records with a higher watermark in the listing it came from.
The record holding the global maximum has no higher record, so it can never be deleted, whatever the listing:
stale, partial, cut short by pagination, or missing the worker's own newest write. The high-water mark therefore
never decreases, so pruning cannot remove the evidence needed to detect a rollback. Consequences:
* interrupted pruning leaves extra records only;
* workers that share an ID (misconfiguration), or whose raw IDs sanitise to the same string, may prune each other's
  records, which still keeps the newest `KEEP` of that ID and never the maximum;
* a pruning failure never fails the effect: the record was already written before the prune began.

**Tests.** `unit::test_witness_pruning` - exact identity with suffix and prefix look-alikes (`w1`, `a-w1`, `w1-x`,
`1`, `w`); candidate selection; a randomised model (40 seeds x 119 writes) with stale, paginated and arbitrary partial
listings, shared IDs and interruptions after any number of deletes, asserting after every step that the maximum
survives; 5 threads (two sharing an ID) writing and pruning one directory with a concurrent reader that never sees the
mark decrease; an interrupted prune. `s3w::test_pruning_follows_every_page_and_matches_exact_identity` (page size 2)
and `s3w::test_interrupted_prune_on_s3_never_lowers_the_mark` against SeaweedFS. Mutations that delete all own records
or restore suffix matching are caught. These tests establish the algorithm; the storage properties listed below remain
**unverified for any production store**.

### Support levels
All three ticket integrations are **fixture-tested** against local fakes and have never met the real services:
* Jira-style: shapes from Atlassian's REST v3 documentation; search is documented as not read-after-write consistent.
* ServiceNow-style: Table API shapes from ServiceNow's documentation, which says nothing about idempotency or
  read-after-write consistency; table, correlation field and state mapping are per-instance assumptions.
* GitHub Issues: REST 2022-11-28 shapes; the operation key is a marker line in the issue body (label-name length
  limits are not documented on the labels page); lookup scans recent issues and is bounded.
None declares deduplication, so the same rule applies: adopt on a lookup hit, otherwise park after an uncertain create
(`wf::*`, 6 scenarios x 3 adapters). Inbound polling records ticket state append-only and never moves the case.

### Amendment (2026-10-24): who may transition an execution after the effect

Two responsibilities are separated after the effect step.

* **Observations** of the provider's answer (created, adopted, rejected, outcome unknown) are recorded by the effect
  gate in `effect_intents` and job events even after the worker's lease is lost, because the effect may exist and
  that fact must not be lost. Unchanged.
* **Transitions of the execution record** are decisions taken for the job: `succeeded` (with the external reference,
  consuming the approval use), `reconciling`, `failed` or `cancelled` (returning the use if no attempt was made). Each
  now commits only in a transaction that first passes the job's lease check (`JobContext.fenced`), so it is made by
  the holder of the current lease token. An execution belongs to one job (`job_id` is immutable), so that token
  identifies the attempt. A worker that has lost the lease records its observation as `execution_transition_discarded`
  and stops; the current lease holder reruns the step and the gate reconciles from the recorded intent (a recorded
  success is adopted, never created again).

**What was wrong (confirmed against PostgreSQL, verification run 32).** Without the fence, a worker whose lease had
expired could transition the execution after another worker had reclaimed the job. In the reproduced interleaving the
first worker's gate denied (the approver's membership was suspended), its lease expired, the membership was restored,
and the second worker passed its checks; the first worker then marked the execution `failed` and returned the approval
use, and the second created the ticket. The record said `failed` with no external reference while the ticket existed,
and the single-use approval ran again and created a second ticket.

**Operator adoption.** With the stale success no longer applied, a job parked by the current worker stays parked while
the recorded intent already says `succeeded`. Adopting then left the job `succeeded` and the execution `reconciling`
with no reference, because no open intent remained to re-run; on `main` the same path was reachable after a restore
park. Adoption that finishes the job now finishes the execution (`succeeded`, `adopted_by_operator`, unverified), and an
adopted reference that contradicts a recorded success is refused (`effect_evidence_conflict`). `not_applied` already
reconciled from the recorded success without a second create.

**Not changed, known.** A cancellation that the job runner applies at claim time (the previous worker's lease expired
while `cancel_requested` was set) cancels the job but leaves the execution open (`prepared` or `executing`) and its
reservation `reserved`; nothing finishes it. Reproduced (verification run 32); fixing it needs a decision on the record
when an attempt may already have reached the provider, where `cancelled` would be false. Separately, `abandon` still
records `failed` although the effect may exist, as documented above. None of this is exactly-once execution: a request
already sent cannot be withdrawn, and only provider deduplication or fencing stops a second one (above). (Both
addressed by the amendment of 2026-10-25 below.)

### Amendment (2026-10-25): cancelling does not establish that an effect was cancelled

**Rule.** Cancelling an execution stops its scheduling. It does not establish that the external action was cancelled,
and the absence of a response is never evidence that nothing happened. The execution's outcome is decided from the
effect evidence, in one transaction with the approval accounting.

**Evidence** (`effect_evidence` in `domains/actions/service.py`). The gate writes the intent, and marks it
`executing` with an `effect_attempt` job event, in a transaction that commits before any request is sent; so those
records are written ahead of every dispatch.

| Evidence | Established when |
|---|---|
| recorded success | the intent is `succeeded` or `reconciled` with an external reference |
| recorded failure | the intent is `failed` (provider rejected) or `abandoned` (operator) |
| never began | no intent, or a `prepared` intent whose every authorized dispatch is accounted for as not applied (the provider reported it definitely not applied under that dispatch's lease token, or an operator later resolved `not_applied`); **and** the database can vouch for its effect records (no fingerprint change, fingerprint acknowledged, job not carried across a recovery acknowledgement) |
| may have begun | anything else: an `executing` or `unknown` intent, an unaccounted dispatch (for example a stale worker's request still in flight after a repeat was refused), or restore doubt |

**Settlement** (`settle_cancellation`), resulting states:

| Evidence | Execution | Reservation | Job |
|---|---|---|---|
| never began | `cancelled` | `released` (use returned), same transaction | `cancelled` |
| recorded success | `succeeded` from the record, reference marked unverified | `consumed` | `succeeded` |
| recorded failure | `failed` | `consumed` | `cancelled` |
| may have begun, or the execution is already `reconciling` | `reconciling`, with `external_effect: unknown` and why the reservation is held in `outcome_detail` | stays `reserved` and keeps counting against the approval, so no fresh execution can reuse it | `needs_operator`, reason states the use stays reserved |

A recorded success whose object failed verification is held, not settled as succeeded.

**Where it runs.** `cancel_execution` sets `cancel_requested` and settles at once only a job no worker holds
(`queued`, `waiting`, `needs_operator`). A running job is settled by the worker: at claim time, when the previous lease
has expired (the claim holds the job's row lock and no lease is valid), or in the lease holder's final write. Both go
through the handler's `on_cancel` and `jobs.core.settle_cancelled_job` (ADR 0006 amendment 3). The handler's own step
no longer decides on its own that a cancelled execution sent nothing. `cancel_requested` stays set, so after an operator
resolves a held cancellation the next claim settles it again from the new evidence: `adopt` ends `succeeded`,
`not_applied` ends `cancelled` with the use returned, `abandon` ends `failed` with the use consumed. With cancellation
requested, `not_applied` does not re-run the effect.

**Races.** Cancel against the gate's authorization: the gate re-reads the job row under its lock at the authorization
(step 3) and stops if cancellation was requested; a settlement reads the intent under lock after locking the job row.
So either the authorization committed first (intent `executing`, the cancellation is held) or the settlement did (the
job is no longer running under that token and the gate's fenced authorization fails; nothing is sent). A worker paused
before the authorization therefore sends nothing; a worker paused after it may still send, and its late answer is
recorded on the intent as an observation without the authority to transition the execution (amendment of 2026-10-24).
`cancel_execution` and `reconcile` now lock the job row before the execution row, the order the worker uses.

**Abandon** (established before the change, verification run 33). Abandoning records that the operator could not
establish the outcome. Before this change it returned the use when no intent existed, which is the case for a job the
restore witness parked before writing an intent: the single-use approval then authorized a fresh execution. Abandon now
always consumes the use and records `external_effect: unknown`. An operator who has established that nothing was sent
cancels the execution and resolves `not_applied`, which returns the use through the evidence rule above.

**Generic job operations.** `/jobs/{id}/cancel` and `/jobs/{id}/resolve-effect` changed an action job without its
execution and approval use (for example a cancelled job with a `prepared` execution and a `reserved` use). They now
refuse action execution jobs (`settled_with_aggregate`); `/action-executions/{id}/cancel` and `/reconcile` settle both
together. This narrows what `job.operate` can do; no permission was added.

**Adoption the gate cannot verify (review finding on this change's earlier head).** The adoption fix of 2026-10-24
finished the execution `succeeded` from whatever reference the operator typed whenever no open intent was left. Before,
an adopted reference was always checked by the gate and `adapter.verify` before the execution succeeded. On `5e17eff` an
operator could mark a witness-parked execution (no intent, no ticket) `succeeded` with an invented reference, and close
one whose recorded object had failed verification. Adoption without an open intent now finishes the execution only from
a recorded success that matches the reference and is not contested; otherwise it is refused
(`effect_evidence_missing`) and nothing changes. Unverified adoption remains possible only through what the gate
records. A requested cancellation settled from an operator's adoption (`reconciled` intent) is recorded unverified.

**Lock order of observations.** The gate's unfenced observation writes (the outcome record and a lookup adoption) now
take the job row in `KEY SHARE` mode before the intent, the order every other writer uses, so an observation and a
cancellation settlement cannot deadlock. Not covered by a dedicated test.

**Residual limitations.**
* A witness-parked execution with no intent cannot be adopted; the operator abandons it (use consumed) or resolves
  `not_applied` after establishing that nothing was sent.
* The settlement in the API path (`cancel_execution` on a job no worker holds) uses only the database's own restore
  signals; it does not read the external restore witness, which the worker's preflight and the gate do. After a
  same-identity restore that only the witness detects, cancelling a never-run job there would return its use.
* A held cancellation always needs an operator; a lookup-capable integration does not reconcile a cancelled job by
  lookup on its own.
* A success settled from the record is not verified against the provider (`verified = false` on the reference).
* The database guard on releasing a use still checks only that no intent left `prepared`; restore doubt and
  unaccounted dispatches are enforced by the application under the trusted runtime credential (ADR 0012 a4).
* Handlers without `on_cancel` keep the previous cancellation behaviour.
* Abandon cannot return a use even when nothing was sent; use cancel and `not_applied` for that.
* Not exactly-once: a request already sent cannot be withdrawn; only provider deduplication or fencing stops a second.

## Consequences
Parks are more frequent than with a naive lookup-then-create policy (every uncertain Jira-style create needs an
operator unless the index has caught up). That is the price of not creating duplicates. A provider with
idempotency keys, unique external identifiers or fencing removes most parks.

## Not tested
Live Jira, ServiceNow or GitHub; the S3 witness on any store other than SeaweedFS; witness in a separate account; point-in-time recovery (archive
recovery creates a new timeline per PostgreSQL documentation, so the fingerprint should change, but this was not run);
load beyond 4 workers by 12 executions.
