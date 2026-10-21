# ADR 0006: Durable workflow engine

Status: **accepted** (2026-10-22). The recommendation below was presented to the project owner, who replied "Proceed" at
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

## Revisit triggers (choose Temporal, or Temporal Cloud subject to residency and commercial review, if any occurs)
* Investigation or remediation workflows need more than a few durable steps with compensation or fan-out.
* The owned runner's incident rate or maintenance cost exceeds an agreed threshold.
* A dedicated-install customer already operates a secured Temporal cluster and requires it.

## Not tested (either engine)
Production Temporal cluster and its persistence; Temporal authoriser/mTLS configuration; load and throughput;
replication and failover; point-in-time recovery; network partitions; cancellation after an external call started;
multi-step workflows.
