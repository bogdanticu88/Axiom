# ADR 0014: Verification worker

Status: accepted (2026-10-22, checkpoint 7). Tested **only against a local fixture check endpoint** (a TLS server in
the test process with a throwaway CA, `tests/integration/check_target.py`). No scanner, check service or other
external system has been integrated or called.

## What already existed (requirements and workflow, inspected first)
* Specification §10: verification identifies the deployed asset version and tests the original condition plus the
  applicable acceptance criteria; results are passed, failed or inconclusive; unavailable systems or incomplete scans
  produce inconclusive, never passed.
* Workflow: `awaiting_verification` → stays there on a pass (a person then closes with `closure.propose`), →
  `remediating` on a fail, → `review_required` on inconclusive (`model.workflow_after_verification`).
* `CaseService.record_verification`: needs `verification.record` at the case scope, the latest remediation report,
  a recorder other than the reporter, explicit criteria; resolves the observed deployment; **recomputes** the outcome
  (`model.verification_outcome`: pass only on the reported deployment with complete coverage and verified evidence;
  a claimed pass is only downgraded); inserts `verification_runs` with a `verification_review` decision.
* Database: `verification_runs` is append-only and cannot hold a pass without complete coverage, an observed
  deployment and evidence; the decision guard (0016/0017) lets a workload record `verification_review` only while it
  holds `verification.record` at the case scope. Before this ADR no workload held that permission.
* Register: VER-04 (automated verification worker) planned; the implementation plan names "scoped check
  credentials".

There is no separate acceptance-criteria model: the only criterion the worker can state is the original condition
(the case's vulnerability references and components on the reported asset). That is what it checks.

## Decision

### Identity and authority
* One **verification identity per tenant**: a workload principal created by the provisioning identity
  (`python -m axiom.provisioning create-verification-identity --tenant ... [--scope ...]`) and recorded on
  `axiom.tenants.verification_principal_id`. It is not the tenant system principal and not the person who queued the job.
* It holds one role, `verification_worker` (workload-only), with exactly `verification.record`, `evidence.upload` and
  `evidence.read:confidential` (citing evidence requires read permission at its classification). No case creation,
  reopening, closure, assessment, approval or risk permission. Binding it at a project limits it to that project.
* System authority was not broadened: the ingestion system principal's role is unchanged.

### When a check runs
* `report_change` enqueues `case.verification_check` in the same transaction when an active connection with adapter
  `verification_check` covers the case scope (the scope or an ancestor; nearest wins). Dedupe key
  `verification:<report id>`: one job per reported change. The payload holds the case and report IDs only.
* A connection holds the endpoint's HTTPS base URL, an optional `secretref:` credential (sent as a bearer token) and
  `max_observation_age_seconds` (default 3600, bounded 60–86400). Configuring one needs `connection.configure`.

### The step, and its authorization and commit boundary
Every phase runs as the verification identity; authority is re-read from current rows each time.
1. **Read** (one transaction): the job lease is held; nothing is recorded for this job yet; the case still awaits
   verification of this report and has no verification for it; `verification.record` and `evidence.upload` are held
   at the case scope; a covering connection is active.
2. **Observe** (no transaction open): POST `axiom-check/1` to the endpoint (redirects not followed, 15 s timeout, 1 MiB
   cap, credentials only in the `Authorization` header); apply the rules below; store the response body as
   confidential evidence (finalised, so its digest is verified).
3. **Commit** (one transaction): the job row is locked and the lease re-checked; `record_verification` re-checks the
   state, the case version read in phase 1 and `verification.record` (bindings and membership share-locked until
   commit, ADR 0012 amendment 3); the run, its decision and the observation's provenance row commit together.

Revocation: before phase 1 or between phases → the next permission check refuses, the job **fails**
(`authority_missing` / `authority_revoked`) and nothing is recorded (evidence stored in phase 2 remains, attributed to
the worker); during phase 3 after its check → the revocation waits for the commit. A check can therefore be
*performed* by an identity whose authority is revoked moments later, but it is *recorded* only if the authority holds
at commit. No instantaneous revocation is claimed.

### Outcome rules (`verification/checks.py`; first match decides)
| Rule | Outcome |
|---|---|
| no vulnerability reference on the reported asset (`no_checkable_condition`) | inconclusive (endpoint not called) |
| connection error, timeout, HTTP 429/5xx | retried with backoff; on the job's last attempt inconclusive (`target_unavailable`) |
| any other non-200 status, including redirects (`target_refused`) | inconclusive |
| oversized, non-JSON, wrong schema or request id, malformed fields (`malformed_response`) | inconclusive |
| no valid deployment digest (`deployment_unknown`) | inconclusive |
| no valid RFC 3339 observation time (`observation_time_unknown`) | inconclusive |
| observation more than 5 minutes in the future (`observation_time_in_future`) | inconclusive |
| observation older than the maximum age (`observation_stale`) | inconclusive |
| observation before the change was reported (`observation_predates_change`) | inconclusive |
| a different deployment was examined (`different_deployment`) | inconclusive |
| one criterion reported with different results (`contradictory_results`) | inconclusive |
| the condition is present (`condition_present`) | **failed** |
| partial coverage, or a criterion missing or `error` (`incomplete_coverage`) | inconclusive |
| every criterion absent with complete coverage (`condition_absent`) | **passed**, if the case service agrees |

The case service recomputes the outcome; a unit test checks that across every rule only `condition_absent` with
verified evidence can end as passed.

### Provenance and separation from human decisions
* `axiom.verification_observations` (migration 0018): connection, adapter, endpoint origin, request digest, request and
  response times, HTTP status, response digest, evidence, the endpoint's observation time and examined digest, rule,
  attempts, job, lease token and worker. Append-only; one per job and per run; insertable only by the bound principal
  for a run it recorded in the same transaction.
* The decision is a `verification_review` by a principal whose kind is `workload` (from the identity record); the
  audit trail and history carry that kind. Closing after a pass, accepting risk, approving actions and every other
  discretionary decision stay with people; the worker cannot reopen cases.
* The UI labels worker results "automated check (worker)" with "Fixture-tested integration", shows source, the
  endpoint's observation time and rule, and keeps "recorded by a person" for human results.

### Duplicates, retries, crashes, stale versions
* Lease fencing: a step that lost its lease writes nothing (tested by stealing the lease while the endpoint answers).
* Crash after commit: the next claim finds the observation for the job and finishes (tested by killing `_finish`).
* Case changed during the check: phase 3 fails on the version, the job retries, and phase 1 then skips because the
  case was verified meanwhile (tested with a person verifying during the check). Nothing is overwritten.
* Backstops: `UNIQUE (tenant_id, job_id)` and `(tenant_id, verification_run_id)` on observations, the job dedupe key,
  and the expected case version.

## Consequences
* A pass still needs a person to close the case. A fail returns the case to remediation without a person; an
  inconclusive result sends it to review.
* Orphaned evidence can accumulate from retried or refused steps; it is attributed and auditable but not cleaned up.
* Changing the worker's behaviour needs a new handler version (`case.verification_check` v1).

## Not done or not verified
* Any real check endpoint, scanner or rescan service; certificate trust for one; the `axiom-check/1` contract is the
  platform's own and no external product implements it.
* Acceptance criteria beyond the original condition; criteria per case or per remediation plan.
* A human-requested re-check (a second job for the same report); today one automated check runs per reported change.
* Scheduling a check after a delay (for example waiting for a rollout to finish).
