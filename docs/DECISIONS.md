# Decisions index

Architecture decision records live in `docs/adr/`. Decisions taken in the design documents themselves are listed for
completeness.

| ID | Title | Status | Summary |
|---|---|---|---|
| P-14 | Shared and dedicated installations | approved by the project owner, 21 Oct 2026 (Plan 14) | One codebase; tenant is the data and authority boundary in both modes |
| [0001](adr/0001-repository-layout-and-package-name.md) | Repository layout and package name | accepted | `axiom` instead of `platform` (stdlib clash) |
| [0002](adr/0002-tenant-isolation.md) | Tenant isolation | accepted for Phase A | Forced RLS, composite FKs, transaction-bound context; RLS does not contain a compromised app |
| [0003](adr/0003-database-roles-and-migrations.md) | Database roles and migrations | accepted | Cluster roles provisioned separately; checksummed ledgered migrations |
| [0004](adr/0004-case-command-guards.md) | Case command guards and closure routes | accepted | Service plus DB guards; asset-retirement route; deferral; R7 return to review (approved, implemented); RISK-02 resolved |
| [0005](adr/0005-evidence-storage.md) | Evidence storage and finalisation | accepted | API-streamed uploads, read-back hash verification, SeaweedFS for Compose |
| [0006](adr/0006-workflow-engine.md) | Durable workflow engine | **accepted, provisional** (2026-10-22); operating limits and switching criteria documented | PostgreSQL-backed job runner for Phases B-D; Temporal as named alternative with explicit revisit triggers |
| [0007](adr/0007-dependency-pinning.md) | Dependency pinning | accepted | uv lock with cooldown; digest-pinned images |
| [0008](adr/0008-authentication.md) | Authentication | accepted for development; interactive sign-in superseded by 0013 | Bearer-token validation for API clients; development tokens refused in production |
| [0009](adr/0009-ingestion-pipeline.md) | Ingestion pipeline, source identity, asset correlation | accepted for Phase B | Fenced page commits, coverage rules, strong/weak identifiers, no automatic merges |
| [0010](adr/0010-action-protocol-and-duplicate-prevention.md) | Action protocol, duplicate prevention, restore detection | accepted | DB-computed proposal digests; approvals bound to version and digest; locked reservations; capability-based effect gate (no repeat without provider dedupe or fencing); external restore witness; audited pruning invariant |
| [0012](adr/0012-evidence-backed-investigation.md) | Evidence-backed investigation | accepted (initial limits D-INV-1); real provider unverified | Frozen snapshots with contradictions and gaps; approved per-tenant model routes, no fallback, classification withholding of content and metadata, redaction; durable runs with budgets and recovery; read-only typed tools; claim validation (rejected / downgraded / references_checked, never entailment); human review before use in an assessment. Amended at checkpoint 5: claim checks are deterministic record checks (existence, membership, availability, identifier equality, recorded status, freshness, scan-time-ordered contradictions, deployment scoping), never semantic relevance or entailment; unresolved contradictions stay open; system identities record only policy-authorised results. Amendment 2 (checkpoint 6): the database checks the actor's real role bindings for system results instead of trusting the authority JSON; workload principals hold only workload roles; full inventory of system actions |
| [0011](adr/0011-policies-ownership-sla-and-reporting.md) | Policies, ownership routing, SLA clocks, report semantics | accepted (thresholds provisional) | Versioned policies with independent publishing; deterministic priority with recorded limitations; expiring overrides reassessed by policy with provenance; read-only impact preview; rule-based ownership with unresolved queue and no authority; triage vs remediation clocks, revise-not-reset; as-of reproducible reports with per-source coverage and freshness; classification-aware evidence packages |
| [0013](adr/0013-enterprise-sign-in-sessions-and-analyst-ui.md) | Enterprise sign-in, browser sessions, analyst UI | accepted; **local Keycloak only, Entra not tested**; amended at checkpoint 6 (deprecated Authlib client replaced, internal discovery URL, start-up secret check, UI and Keycloak in Compose) | OIDC code flow with PKCE (Authlib, joserfc); identity by issuer and subject, never email; single-use browser-bound login state; hashed server-side sessions with CSRF; development tokens refused in production; React/TypeScript UI at /ui under a strict CSP with honesty labels and explicit error states |

## Proposed specification changes awaiting approval
| Ref | Proposal | Why | Status |
|---|---|---|---|
| R7 | Allow `remediation_planned -> review_required` and `remediating -> review_required` with an authorised decision | No way to abandon a plan today without a fake verification | **approved by the project owner 2026-10-22 (Option A with conditions); implemented** (ADR 0004, migration 0008, Specification S 4 amended) |

## Interim defaults pending business decisions
| Ref | Default in force | Where | Decision needed |
|---|---|---|---|
| D-RISK-1 | Independent risk authorisation for pending/urgent/high priority or more than 90 days; maximum 365 days; requests lapse after 14 days; reassessment notice 14 days before expiry | `RiskPolicy` (stored with each request) | Approval thresholds (Specification S 17) |
| D-ACT-1 | `ticket.create` approvals: at most 3 uses; proposals expire within 30 days | `domains/actions/model.py` | Approval thresholds (Specification S 17) |
| D-SLA-1 | Superseded by D-SLA-2 (migration 0012 replaced the single SLA timer) | - | - |
| D-SLA-2 | Triage 7 days from case creation or reopening; remediation from first prioritisation: urgent 7 days, high 30, medium 90, low 180; a deferral pauses the remediation clock only with an authorised reason (vendor_fix_pending, change_freeze, awaiting_risk_decision); calendar days, no business hours | Built-in default in `domains/policies/service.py`, replaceable by a published `sla` policy; recorded on every timer | SLA policy (Specification S 17) |
| D-PRIO-1 | Priority matrix (source severity x asserted criticality) with unknown severity and unknown criticality treated as high | Built-in default; replaceable by a published `priority` policy | Prioritisation policy (Specification S 17) |
| D-FRESH-1 | Source freshness: default 168 h; Tenable and Azure Resource Graph 48 h; Trivy and SARIF 336 h | Built-in default; replaceable by a published `freshness` policy | Operational targets per source |
| D-INV-1 | Investigation budget defaults: 4 rounds, 8 model calls, 12 tool calls, 200k input / 32k output tokens, 5,000,000 cost micro-units, 900 s deadline (caps 10 / 30 / 50 / 2M / 200k / 100M / 3600 s); one corrective retry for malformed output; provider retries per route (0-3); evidence excerpts 4096 bytes per call | `investigation/service.py`, `runner.py`, `tools.py` | Cost envelope and model policy (Specification S 17) |
| D-PRIO-2 | Priority overrides expire after 90 days by default, at most 365; on expiry the current policy is re-applied (never the earlier priority restored) | `domains/cases/priority.py` | Override validity and review policy (Specification S 17) |
| D-EVAL-1 | Evaluation labels and rationales drafted by the author; independent review **pending** (procedure: evaluation/REVIEW-PROCEDURE.md). No held-out set: H1-H10 are a regression set after exposure (evaluation/EXPOSURE.md) | evaluation/cases.json (eval-cases@4) | A named independent reviewer; a new held-out set written by someone else; release thresholds (EVAL-06) |
| D-UI-1 | Browser sessions: 8 h absolute, 30 min idle; login attempts valid 10 min | `config.py` (`ui_session_ttl_seconds`, `ui_session_idle_seconds`) | Session policy of the organisation's security team |
| D-SYNC-1 | Inbound ticket polling, SLA and ownership sweeps every 15 minutes per tenant | `workers/jobs.py` | Operational targets |

## Business decisions still open (from the specification, section 17)
Product name and licence; supported vendor editions and test accounts; approved model providers and offline-model
needs; volumes, retention and cost envelope; exact prioritisation policy, approval thresholds and evaluation release
thresholds. These do not reduce scope; they block only the specific items noted in REQUIREMENTS.md.
