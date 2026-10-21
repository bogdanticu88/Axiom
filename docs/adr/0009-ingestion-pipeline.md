# ADR 0009: Ingestion pipeline, source identity and asset correlation

Status: accepted for Phase B groundwork (2026-10-22)

## Decision
### Runs, pages and fencing
* An ingestion run (`ingestion_runs`) is created `queued` by a permitted user (file import) or by a sync request
  (API connection). A worker claims it with a lease and a **fencing token** that increments on every claim.
* Work is committed **page by page**. One transaction per page writes source records, observations, quarantine
  rows, asset identity changes, occurrences, occurrence history, case creation/links (through the case command
  layer, so audit and events apply) and the page marker. A database trigger refuses the page marker unless the run
  is running and the committing token is current, so a stale worker cannot commit anything (verified, including
  with the service-side check removed).
* Resuming re-parses the preserved original and skips committed pages (same key and digest; a different digest
  fails the run as "source changed"). Checkpoints for API connections advance only in the finalisation transaction
  of a run with complete coverage.
* This mechanism is orchestration-agnostic: whichever engine ADR 0006 selects calls `execute(run)`; correctness
  does not depend on the dispatcher. `axiom.workers.ingest` is an **interim** dispatcher.

### Original evidence
* File imports must reference **verified** evidence the requester can read. The worker re-verifies the stored
  digest before parsing; a tampered original fails the run.
* Every API page is stored as verified evidence (classification `confidential`) before parsing.
* Observations keep `raw_evidence_id`, a locator (JSON pointer or page), the normalised view and the complete source
  record. Imported text is stored as untrusted data and never interpreted.

### Source identity and occurrence history
* `source_records`: one row per (namespace, record type, external ID, source version). External IDs are adapter
  defined and never a CVE alone: Trivy = package identity + vulnerability ID; Tenable = asset UUID + plugin +
  port/protocol; SARIF = fingerprint, else partial fingerprint, else a weak location digest (marked as such;
  identical identities in one run are quarantined, not merged).
* `finding_occurrences` stay scanner-specific and deployment-specific. `occurrence_observations` record each run's
  view: `present`, `fixed_by_source`, `suppressed_by_source`, or `absent_in_complete_scan`.

### Coverage and absence
* Coverage is `complete` only when the source says so (Trivy image report with a registry digest; Tenable export
  FINISHED with no failed or cancelled chunks; Resource Graph not truncated) **and** nothing was quarantined;
  `partial` when the source says it is incomplete or records were quarantined; otherwise `unknown`.
* Absence is recorded only for complete runs whose adapter supports absence inference for an identified deployment
  (currently Trivy with a registry digest; SARIF with VCS revision). Tenable exports and Resource Graph pages never
  imply absence. **Absence never changes a case** (B04, A03). Source-reported fixes (Tenable `FIXED`) are recorded
  as observations and never close cases.

### Asset correlation with explicit uncertainty
* Identifiers are **strong** (registry repository, Tenable asset UUID, Azure resource ID and VM ID, repository URI,
  source-scoped IDs) or **weak** (hostname, FQDN, IPs, names). Strong identifiers are unique per tenant (partial
  unique index); weak ones never are.
* A record must carry a strong identifier, or the importer must declare a subject (stored with origin
  `declared_by_importer`, never as an observation).
* One strong match reuses the asset; strong identifiers pointing at different assets create a new asset marked
  `conflict` plus a `strong_identifier_conflict` candidate; weak overlaps create `weak_identifier_overlap`
  candidates. **Nothing merges automatically.** Reviewers can record `confirmed_same`, `confirmed_distinct` or
  `dismissed`; executing reversible merges and splits (AST-03) is not built yet.
* Business context from tags (owner, criticality, environment) is stored as `source_tag_assertion`, not as observed
  fact, with effective dates.

### Case correlation
New occurrences join an open case for the same asset and vulnerability reference from the same source, otherwise a
new case is created. A new occurrence matching a closed case reopens it (`recurrence`). An existing occurrence seen
`present` again after a **verified** closure reopens the case (the fix does not hold for that deployment). Cross-
scanner correlation (e.g. Trivy CVE vs Tenable plugin) is deliberately not attempted yet.

## Limits
Parsers load whole documents into memory (bounded by the evidence size limit); streaming parsers are future work.
Case correlation is per source system. Tenable and Azure support is fixture-tested against synthetic data and local
fakes only. The interim dispatcher has basic per-tenant batching, not quotas (TEN-10).
