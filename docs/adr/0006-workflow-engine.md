# ADR 0006: Durable workflow engine

Status: **accepted, provisional** (2026-10-22). Evidence-based: it stays in force while the operating limits below
hold and no switching criterion is met; each checkpoint re-states the evidence. The recommendation below was presented to the project owner, who replied "Proceed" at
01:48 local time on 2026-10-22; that reply is recorded here as acceptance. The conditions in "Conditions before
production effects rely on it" remain binding.

## The requirements do not change with the engine
B07, B08, A02, A07, A08, A12, A15 and the action protocol (Plan 7) apply either way. Both experiments confirmed that
the guarantees against duplicate or unauthorised effects come from **platform** mechanisms: canonical proposal
digests, approval records in PostgreSQL re-checked before the effect, a stable operation key, durable intent before
the effect, reconciliation by lookup, operator parking when lookup is impossible, and fencing or idempotency at the
external system. That is true for both engines, so it is **not** an argument for either. The comparison below is
about everything else.

## Evidence
| Run | Result | Log |
|---|---|---|
| Temporal experiment (temporalio 1.34.0, CLI 1.9.1 / Server 1.32.0 dev server, SQLite), full suite incl. security and recovery probes, my independent rerun | **22 passed in 291.36s** | docs/verification/2026-10-22-workflow/temporal-full-rerun.log |
| PostgreSQL-backed experiment (PostgreSQL 16.15, psycopg 3.3.6), my independent rerun | **26 passed in 96.53s** | docs/verification/2026-10-22-phase-b/pg-spike-independent-rerun.log |

Every crash was a real SIGKILL or SIGSTOP of a separate process. Both are experiments, not production engines. The
Temporal security/recovery tests were written in an earlier iteration that was stopped before its report was written; I
read the tests and reran them, and the findings below are from my run.

## Comparison against the same requirements
| Requirement | Temporal (observed unless marked "docs") | PostgreSQL-backed (observed unless marked) |
|---|---|---|
| Worker crash during approval wait | Survived; 10.1s to resume after signal (sticky queue timeout) | Survived; 0.22s after approval (a waiting run is just a row) |
| Server crash | Dev server (SQLite) killed and restarted mid-wait: survived | Own PG 16 cluster SIGKILLed with runs in flight: crash recovery, 21 runs, 21 tickets |
| Durable approval waits and timers | Server-side timers; deadline fired at ~3.1s | `due_at` polling; deadline fired 0.199s late (poll interval) |
| Argument substitution, expired approval | Rejected, 0 tickets | Rejected, 0 tickets |
| Lost acknowledgement | Adopted by lookup (1 ticket); naive retry control: 2 tickets | Adopted by lookup (1 ticket); control: 2 tickets |
| No lookup at the external system | Parks for operator, 1 ticket | Parks for operator, 1 ticket |
| Stale worker (SIGSTOP mid-activity) | Server rejects the stale completion, but the effect still happens: **naive 5 tickets**, platform guard 1, heartbeat gate 1. Detection took 28.6 to 39.1s (timeouts) | Token fencing refuses a stale worker that has not passed the gate (1 ticket). After the gate, only external fencing or dedupe prevents a second ticket (without it: 2) |
| Concurrency and dedupe | Workflow-ID conflict policy: 20 concurrent starts, 1 accepted | 4 workers x 50 runs: 50 tickets, no double claims; also with 2 workers killed |
| Cancellation, revocation | Cancel during wait and during activity (heartbeat-driven, 1.6s); revoked approval re-checked before effect: 0 tickets | Cancel and revocation at the gate: 0 tickets; cancel after the call starts not handled |
| Bounded retries, dead letters | Built in (activity retry policy) | Built by us: backoff observed; dead-letter state; poison run before the gate loops forever (gap) |
| Tenant fairness | Per-tenant task queues isolate well (quiet tenant max 0.38s vs 5.04s on a shared queue); task-queue rate limit works (10 tasks: 0.21s to 7.13s at 2 rps); fairness keys only partly helped in this test (max 4.8s, median 0.41s) | Per-tenant limit in the claim query: small tenant moved from positions 41-44 to 6-11, at a throughput cost (2.38s to 3.79s) |
| Versioning | Replay test detects unpatched changes mechanically (NondeterminismError); patching works; Worker Versioning documented (needs Server 1.29.1 or later, docs) | Handler version pinned per run, drain status, explicit migration; **no automatic compatibility check** |
| Backup and restore | Restoring an older Temporal store re-ran a completed effect: **naive 2 tickets**; platform reconciliation 1. Temporal and PostgreSQL backups have independent timelines | Restore with runbook step: no duplicates; without it: 4 or 5 tickets. One store, one timeline |
| Access control | Default authoriser allows every call (docs). Observed: an unauthenticated client read history, **forged the approval signal and got a ticket created** (original design), and terminated a workflow. mTLS and JWT/ClaimMapper authorisation exist at **namespace and API-call granularity** (docs), not per workflow or signal | PostgreSQL roles, RLS and the platform's own authorisation; same model as the rest of the platform |
| Sensitive data in history | Original design stored proposal text in history. IDs-only design keeps evidence out; AES-GCM codec encrypted 23 of 24 payloads; **still plaintext:** workflow and activity types, task queues, worker identity, signal names, timestamps, search attributes (e.g. TenantId), workflow IDs; failure messages leak unless failure attributes are encoded (observed both ways). Per-tenant keys allow crypto-shredding (decode failed after key removal) | Stays in PostgreSQL under RLS |
| Tenant deletion (A20) | Deleting a tenant's executions removed them from the API (1.1s running, 35.3s closed), but the markers stayed in the SQLite file until it was compacted (VACUUM of a copy removed them). Production persistence behaviour not tested | Inside the platform's own retention and deletion design (not built yet) |
| Operations | Separate stateful cluster: frontend, history, matching, worker services plus persistence and usually a visibility store; Helm chart; upgrades; security plugins (docs) | No new infrastructure; but we own timers, leases, heartbeats, fencing, retries, dead letters, versioning, visibility/ops UI, metrics, retention, backpressure, restore safeguards and CI fault testing (list in experiments/workflow-pg-spike/RESULTS.md) |
| Multi-step workflows | Native (the model pays off here) | Not built; each step needs the same leases, intents and fencing; this is where hand-built code grows fastest |

## Recommendation
**Use a PostgreSQL-backed durable job runner for Phases B to D** (ingestion runs, single-effect actions with
approval waits, verification jobs, expiry and reassessment sweeps), built as a small `axiom.jobs` module from the
experiment, behind an orchestration interface, and **keep Temporal as the named alternative** with explicit
triggers to revisit.

Reasons, in order of weight:
1. **One trust boundary for tenant data.** Platform state, approvals and job state live under the same roles, RLS and
   audit. Temporal would add a second store where, by default, any client can read history, signal and terminate;
   making it safe needs mTLS, a JWT claim mapper or custom authoriser (namespace granularity only), a payload and
   failure codec with per-tenant key management, and care with search attributes and IDs.
2. **One backup timeline.** The restore tests show both engines need reconciliation before resuming. With Temporal,
   two independently backed-up stores can disagree after a restore; with PostgreSQL there is one point in time.
3. **Tenant deletion** is easier to reason about and verify inside our own data model than in Temporal's
   persistence and visibility stores (observed residue until compaction in the dev server).
4. **The workflows needed in B to D are mostly single-effect** with waits and timers. The experiment covered that
   shape, and ingestion already runs on the same lease-and-fence pattern.

What we accept by not choosing Temporal: we build and maintain timers, step timeouts, retries, dead-letter tooling,
an operations view, metrics and restore safeguards, and versioning has no automatic replay check. These are real
costs; the experiment's gap list is the backlog.

## Conditions before production effects rely on it
Close the experiment's gaps in `axiom.jobs`: step timeouts independent of the heartbeat thread; a claim counter so
poison runs dead-letter; RLS-compatible cross-tenant claiming reviewed like the outbox relay; operator tooling for
parked and dead-lettered runs; metrics (queue depth, oldest due run, lease expiries, fenced refusals); a restore
marker that workers refuse to start without; the full kill/fault suite in CI. Every external integration must accept
an idempotency key or fencing token, or be marked lookup-only with operator parking.

### Status of the conditions (2026-10-22, commit after 5a6b898)
| Condition | State | Evidence |
|---|---|---|
| Step timeout independent of the heartbeat | done: the lease is capped at `step_deadline_at` at claim and on every heartbeat, so a hung step loses its lease even while its heartbeat thread runs | job::test_hung_step_loses_lease_at_deadline...; mutation removing the cap is caught |
| Claim counter dead-letters poison jobs | done | job::test_poison_job_dead_letters_after_max_claims... |
| Tenant-safe claiming | done differently from the relay: no cross-tenant role at all; the worker lists tenants through `axiom_auth.active_tenant_workers()` and claims inside each tenant's RLS-bound transaction. Cost: one pass is O(tenants) | job::test_per_tenant_running_cap, ::test_jobs_are_tenant_isolated |
| Operator tooling for parked and dead-lettered jobs | done as a service and API (`/api/v1/jobs`, `/jobs/attention`, `/jobs/{id}`, `/cancel`, `/retry`, `/resolve-effect`; action-specific `/action-executions/{id}/reconcile` with `action.reconcile`). Retry of dead-lettered and failed jobs is the one permitted move out of a finished state (migration 0006). Privileged, audited; never changes approvals. **No UI** | job::test_lost_ack_without_lookup_parks..., ::test_version_pinning... |
| Restore marker | done, extended by ADR 0010 (external witness for rollbacks the fingerprint cannot see): database fingerprint (system identifier, timeline, database OID); workers refuse to run until an operator acknowledges a new fingerprint (`provisioning acknowledge-recovery`); jobs and intents carried across a restore park when the integration has no lookup | job::test_restore_is_detected_and_no_lookup_effects_park (real pg_dump/pg_restore) |
| Metrics | done: `GET /api/v1/jobs/metrics` (tenant, `job.read`) and an opt-in Prometheus endpoint on the worker (`AXIOM_WORKER_METRICS_PORT`): jobs by kind and state, oldest due age, last-hour lease expiries, fenced refusals, parks, adoptions, attempts, denials, operator retries; per-process counters | job::test_worker_metrics_endpoint..., actions_api::test_parked_execution_reconciled_through_the_api |
| Kill/fault suite in CI | **partly done**: `scripts/ci/run.sh` runs the full suite (real SIGKILL, restore drills, concurrency) on a fresh cluster, the physical snapshot drill and the Compose smoke; `.github/workflows/ci.yml` runs that script. Executed locally only; the hosted workflow has never run (nothing pushed) and its actions are tag-pinned, not SHA-pinned | VERIFICATION run 13 |
| Integrations accept idempotency keys or fencing, or are lookup-only with parking | enforced by the `EffectAdapter` contract; no real integration exists yet | |

## Operating limits (what has actually been exercised)
| Dimension | Exercised so far | Not known |
|---|---|---|
| Concurrency | 4 worker threads x 12 action executions with no duplicate claims or effects; 8 concurrent reservation requests | Behaviour above that; no load test |
| Tenants per pass | Tests run with a handful of tenants; a pass is O(tenants) (one transaction per tenant) | Pass latency at hundreds of tenants |
| Job shape | Single-effect jobs, waits, retries, dead letters, operator retry | Multi-step workflows with compensation (not built) |
| Effect watermark | One database sequence for the installation (no row contention) | Throughput limits of the witness store under load |
| Scheduling | Per-tenant schedules bucketed by interval (risk 1 h, SLA and ticket sync 15 min) | Clock skew between workers beyond tests |
| Recovery | Real SIGKILL, SIGSTOP-like holds, pg_dump/pg_restore, same-OID restore, physical snapshot rollback | Point-in-time recovery, replication failover |

## Switching criteria (re-evaluate Temporal, or Temporal Cloud subject to residency and commercial review)
* Any revisit trigger below occurs.
* A pass over all tenants exceeds the scheduling interval of the shortest schedule (15 minutes) under normal load, or
  per-tenant fairness cannot be kept without a cross-tenant claim path.
* More than two runner defects per quarter that cause a lost decision or an unreconciled effect.
* Phase C or later requires durable multi-step workflows that the single-step model would have to emulate.

## Revisit triggers (choose Temporal, or Temporal Cloud subject to residency and commercial review, if any occurs)
* Investigation or remediation workflows need more than a few durable steps with compensation or fan-out.
* The owned runner's incident rate or maintenance cost exceeds an agreed threshold.
* A dedicated-install customer already operates a secured Temporal cluster and requires it.

## Not tested (either engine)
Production Temporal cluster and its persistence; Temporal authoriser/mTLS configuration; load and throughput;
replication and failover; point-in-time recovery; network partitions; cancellation after an external call started;
multi-step workflows.

## Amendment 1 (2026-10-24): an expired lease is lost, everywhere

**Contract.** A lease is held only while its token matches, the job is `running` and `lease_expires_at` is in the future
by the database clock. An expired lease is lost: only a new claim, with a new token, can take the job again. Nothing
documented allows a heartbeat or a final write to revive it.

**What was wrong.** Two places did not apply the expiry part. The worker's final write (`_finish`) checked only the
token and the state, so an outcome returned after the lease expired, before another worker reclaimed the job, was
written: success, failure, retry, wait, operator parking or cancellation. The heartbeat checked the token, the state and
the step deadline, so it renewed a lease that had already expired. A worker whose lease had expired could therefore
regain it and then pass the final write. Separately, an expiry test placed inside a locking query is evaluated before
that query waits for the row lock. In PostgreSQL (READ COMMITTED), if the transaction it waited for only locked the row,
that earlier evaluation stands, so a lease that expired during the wait was still accepted. If that transaction changed
the row, the condition is evaluated again on the new row version.

**Decision.** One check, `core.lock_held_lease`, authorizes every write a lease holder makes to the job row (the
attempt counter, the heartbeat, the final write) and every handler transaction that calls `JobContext.fenced`: lock the
job row by token and `running` state, then, with the lock held, test `lease_expires_at > clock_timestamp()`. The heartbeat renews only a lease that passes that check,
still never past the step deadline. When it finds the lease lost, it records `heartbeat_lease_lost` with the reason and
stops; it does not revive the lease.

**Guarantee, stated precisely.** The lease was valid at the locked check. It is not promised to be valid at commit: it
may expire after the check. Until this transaction commits it holds the row lock, and a reclaim needs that lock (`claim`
uses `FOR UPDATE SKIP LOCKED`), so no other worker can take the job during the transaction. That rules out a competing
reclaim; it does not make a slow transaction harmless in other ways.

**Handler writes not covered.** Handler writes made without `JobContext.fenced` are not authorized by the lease, on
`main` before this amendment as after it. Two are deliberate and documented in code: the effect gate records what it
observed outside the database (effect intents and their events) even after losing the lease, because those are facts
about the external world. One is a known gap, unchanged here: after the effect step, the action execution handler
updates the execution record (`succeeded`, `failed`, `cancelled` or `reconciling`) without re-checking the lease
(`domains/actions/jobs.py`). A worker that lost its lease after the effect can still write that record. Terminal
records are not overwritten, and the recorded facts were established while the lease was held or observed externally,
but it is not lease-fenced. (Closed by amendment 2, which also shows that a denial established while the lease was held
can be outdated by the time a stale worker writes it.)

**Outcome versus effects.** A discarded outcome leaves the job `running` for another worker to reclaim. It does not undo
writes the handler committed in its own fenced transactions before the lease was lost, or effects outside the database;
the reclaiming worker runs the step again, and effects rely on the idempotency and reconciliation rules above.

**Database enforcement.** Lease expiry is enforced by the worker, not by the `jobs_guard` trigger. The runtime
credential (`axiom_app`) is shared by the API and every worker and may update the lease columns, so a database rule on
expiry could not stop its holder, who could move the expiry first. That holder is trusted and can already act as any
principal (ADR 0012 amendment 4). Leases coordinate cooperating workers against crashes, hangs and pauses, not against the
credential holder. The trigger keeps enforcing the structural rules: the token and counters never decrease, a finished
job cannot change, and job events are append-only. Verification run 31.

## Amendment 2 (2026-10-24): action execution transitions are fenced

The gap named in amendment 1 is closed for the action execution handler. After the effect step, every transition of
the execution record (succeeded, reconciling, failed, cancelled, and the approval use it consumes or returns) commits
only in a transaction that first passes `JobContext.fenced`. A worker without the lease records what it observed as the
job event `execution_transition_discarded` and stops; the effect gate's own records of the provider's answer are
unchanged and still written after lease loss. Details, reproductions and remaining gaps: ADR 0010 (amendment of
2026-10-24) and verification run 32.

## Amendment 3 (2026-10-25): a requested cancellation is settled by the handler

Requesting cancellation stops scheduling; for a job with an external effect it does not establish that the effect was
cancelled. A handler may define `on_cancel(conn, ctx, job, witness)`, which decides the job's outcome from what the
handler has on record; the worker passes its restore witness, which a decision relying on records being complete must
check in the same transaction (`witness.release_clearance`). The worker calls it with the job row locked in two places: while claiming a job whose cancellation was
requested (no worker holds a valid lease then), and in the lease holder's final write when cancellation was requested
and the step did not finish `Done`. `jobs.core.settle_cancelled_job` applies the result: `Fail` cancels the job, `Done`
marks it succeeded, `NeedsOperator` parks it for an operator instead of cancelling it. A claim-time settlement that
raises is rolled back to a savepoint and the job is left for the next claim. Handlers without `on_cancel` are unchanged.
The action execution handler is the only one that defines it (ADR 0010, amendment of 2026-10-25).

