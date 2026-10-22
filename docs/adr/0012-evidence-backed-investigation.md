# ADR 0012: Evidence-backed investigation (Phase C)

Status: accepted (2026-10-22). Budgets, retry limits and the claim rules are initial values (D-INV-1).
The real-provider path is implemented but **unverified**: no credentials or external access were authorised.

## Context
Analysts recorded assessments by hand. Phase C adds AI-assisted investigation, under these constraints:
* AI output is analysis, never authority;
* every conclusion must be traceable to frozen evidence;
* contradictions and missing information must survive;
* data must not leave for unapproved destinations;
* a model or imported content must not be able to widen tools, network access or permissions.

## Decision

### 1. Frozen evidence snapshots (`investigation/snapshots.py`, migration 0013)
A snapshot of one case at one instant has append-only members. Each member has a stable key (`M001`...), a kind, the
record ID, a version identity (observation digest, deployment digest or evidence digest), a classification, a
collection time, a freshness value and availability. It also holds a frozen copy of the attributes used.

Members cover:
* active linked occurrences and their asset versions and assets;
* every observation of each occurrence by every run (present, absent in a complete scan, fixed or suppressed by the
  source);
* the runs themselves (adapter, declared scope or subject, coverage), with freshness under the freshness policy in
  force at that time;
* business-context versions;
* raw reports, and evidence cited by earlier decisions.

**Contradictions** are recorded, not resolved: present in one run and absent or fixed in another (with the latest
status), severity disagreement, user and source context disagreement, and several deployment versions.

**Gaps** are recorded: no complete scan, stale complete scan, no business context, no criticality, no severity,
unverified evidence, and no occurrences.

The digest is computed over a canonical form with times in UTC; `verify_snapshot` recomputes it. Later evidence
produces a new snapshot. An assessment that cites a snapshot keeps it, and a reassessment is a new decision.

### 2. Model routes and the gateway (`investigation/gateway.py`, `providers.py`)
A route records the provider, model, endpoint origin, region, maximum data classification, credential reference,
prices, timeout, retries and output limit. One administrator proposes it, another approves it (service plus a
database CHECK), and the definition is immutable.

The endpoint origin must be in the installation's `AXIOM_MODEL_DESTINATIONS`. The deterministic fake is refused in
production.

A run is bound to one route at creation. The gateway calls only that binding. If the route is disabled, the
destination is unregistered or the provider fails, the run ends; there is **no fallback** to another provider,
model or region.

Every prompt is redacted (credential patterns) and the number of redactions is counted. Members above the route's
classification are withheld, **content and metadata alike** (digest, filename, size, raw locator, normalised fields).
The withholding of metadata was added after a test found digests leaking.

Usage is recorded per call: tokens as reported, or estimated and labelled for the fake, with cost from the route's
prices and the latency.

Providers:
* `DeterministicFakeProvider` is a rule-based stand-in for CI, plus `fake-adversarial:<behaviour>` for tests. It is
  not a language model.
* `AnthropicMessagesProvider` follows the documented Messages API shape. It has been tested against a local transport
  only.

### 3. Durable runs (`investigation/runner.py`, `service.py`)
A run has explicit questions (1 to 10), frozen tool grants, a budget (rounds, model calls, tool calls, input tokens,
output tokens, cost) and a deadline. It executes as a job, one round per fenced job step, and waits between rounds.

At the start of each round the runner checks, in this order:
1. cancellation requested: `cancelled`;
2. the requester no longer holds `investigation.run`: `cancelled` (authority_revoked);
3. route not approved, or gateway refused: `failed`;
4. deadline passed or budget exhausted: `incomplete`.

The model step is recorded as `started` and counted **before** the call. A worker crash leaves it to be marked
`lost` (still counted), and the run resumes.

Failure handling:
* Retryable provider errors are retried up to the route's `max_retries`; then the run is `incomplete`.
* Non-retryable provider errors make the run `failed`.
* Malformed output gets one corrective retry; then the run is `incomplete`.

A run is `completed` only when the model reports done and at least one claim survived validation.

### 4. Claims (`investigation/claims.py`, `schema.py`)
The output schema has no action fields, and unknown fields make the output malformed. `model_stated_confidence` is
an uncalibrated label and is never used as a probability.

Each claim states a subject (vulnerability, asset, attribute) and a conclusion (supported, contradicted, unknown),
citing supporting and contradicting member keys.

**Rejected** when:
* a reference is fabricated, or comes from another snapshot, case or tenant;
* a reference is unavailable (unverified, above the route's classification, or unreadable by the requester);
* the subject is not in the snapshot;
* a reference is valid but concerns another vulnerability or asset;
* a reference's recorded status contradicts what it is cited for;
* a definite conclusion has no record on the cited side.

**Downgraded to unknown** when:
* it ignores a recorded contradiction;
* only stale evidence is decisive;
* the attribute cannot be established from snapshot contents (exposure);
* the latest observation of the subject points the other way. The evaluation harness found that a claim citing both
  sides could otherwise draw the outdated conclusion.

**Every** claim is stored with `entailment = not_verified`. The platform checks references, subjects and recorded
statuses, not reasoning.

### 5. Tools (`investigation/tools.py`)
All tools are read-only:
* `snapshot_member` and `asset_history` take member keys of the run's own snapshot;
* `evidence_excerpt` returns at most 4096 bytes per call, checks integrity, requires the requester's current
  classification permission and the route's classification limit, and audits each read;
* `advisory_lookup` reads OSV `GET /v1/vulns/{id}`. Its fixed template accepts an identifier pattern only. It must be
  enabled in `AXIOM_TOOL_DESTINATIONS` and granted on the run. Reference URLs in its response are returned as text and
  never fetched.

Arguments are typed with unknown fields refused. Output is bounded. Every call, refused ones included, is a recorded
step. Grants are frozen at creation, so content cannot add tools or change permissions or policies.

### 6. Decisions
`record_assessment` may cite `investigation_run_id` and/or `evidence_snapshot_id`. Citing a run requires it to be
completed or incomplete, and requires that **every claim it did not reject has a human review** (confirmed,
rejected, or corrected with a corrected conclusion). The run's limitations and the snapshot's contradiction and gap
counts are appended to the decision's limitations.

Priority stays with the deterministic policy, and the AI has no command path. Database backstops (trigger, using
`axiom_auth.principal_kind`):
* workload principals may insert only `reopen` and `prioritisation` decisions;
* approvals and claim reviews must come from humans.

## Consequences
* Investigations are slower and more constrained than a free-form chat. Many outputs end `incomplete` or carry
  downgraded claims; that is intended.
* The guards depend on structured statuses (presence, absence, freshness). Claims about exploitability or
  reachability cannot be established from scanner data and are downgraded until such evidence types exist.
* The fake provider makes CI deterministic, but it measures nothing about model quality.

## Not done or not verified
* Any real model call. `tests/integration/test_real_provider_optin.py` is opt-in and has never been run.
* Calibration, which is not attempted.
* An investigation UI.
* Per-tenant budgets and quotas (X09).
* Model data-residency policy beyond the route's region label.
* Retention rules for step records.
* Additional evidence types (reachability, runtime, threat intelligence).
* Human-reviewed evaluation references (the current labels are author-drafted).
