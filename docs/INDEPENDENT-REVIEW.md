# Independent review guide

**No independent review has taken place.** Every claim about Axiom's trust boundaries and every evaluation label
so far comes from its author. This guide sets out two separate review tracks for someone who did not build it. They
need different skills and can run independently.

Start from a clean clone of `main`. `docs/IMPLEMENTATION_STATUS.md` ("Current status") says what is claimed and what
is not; `docs/VERIFICATION.md` says how each claim was checked.

## Track 1: authorization and trust boundaries

**Goal:** find a way for a principal to read, change or approve something it should not, or to make Axiom record a
result it should not, within the attacker capabilities below, and check the stated guarantees against the code.

### Entry points
| Entry point | Code |
|---|---|
| HTTP API, bearer tokens, tenant selection (`X-Axiom-Tenant`), error mapping | `backend/axiom/api/app.py`, `backend/axiom/api/operations.py`, `backend/axiom/api/schemas.py` |
| Browser sign-in (OIDC code flow), sessions, CSRF | `backend/axiom/auth/oidc.py`, `backend/axiom/auth/sessions.py`, `backend/axiom/auth/service.py` |
| Authority checks | `backend/axiom/access.py` (`Authorizer`); `axiom.holds_permission` and the decision guard in `backend/axiom/migrations/0016_system_authority_checks.sql`, `0017_authority_hardening.sql`, `0020_principal_status.sql` |
| Tenant and actor context in the database | `backend/axiom/db.py`; `axiom.bind_context` and row-level security in `backend/axiom/migrations/0001_foundation.sql` |
| Provisioning (the only path that creates tenants, principals and workload identities) | `backend/axiom/provisioning.py` |
| Job workers and their identities | `backend/axiom/jobs/`, `backend/axiom/workers/jobs.py`, `backend/axiom/verification/worker.py` |
| Outbound calls to check endpoints | `backend/axiom/verification/checks.py` |
| Idempotency keys | `backend/axiom/idempotency.py` |

### Existing tests to read first
`tests/integration/test_isolation.py`, `test_database_identity_boundary.py`, `test_revocation_boundary.py`,
`test_principal_status.py`, `test_authority_review_cp7.py`, `test_system_authority_boundary.py`, `test_oidc_sso.py`,
`test_tls_deployment.py`, `test_verification_destinations.py`, `test_verification_lifecycle.py`,
`test_api_instants.py`; `tests/unit/test_oidc_validation.py`, `test_verification_checks.py`,
`test_idempotency_legacy_keys.py`. Run them with `scripts/dev/test-db.sh start` and `uv run pytest <file>`.

### Attacker capabilities to assume
1. **An authenticated user of one tenant**, with any role in it, using the API or the browser directly.
2. **A user with roles in two tenants**, trying to carry authority or data across.
3. **A former user**: binding revoked, membership suspended or expired, principal disabled, tenant suspended.
4. **A compromised or dishonest check endpoint** that Axiom's operator configured.
5. **The holder of the shared application database credential** (`axiom_app`). This one is out of scope for
   cross-tenant claims: it is documented to reach every tenant and act as anyone (ADR 0012 amendment 4). Review it only
   for the claims it is said not to break (history cannot be rewritten; no escalation to the owner or migrator roles).

### Guarantees to challenge
| Claim | Where it is stated |
|---|---|
| Requests never act outside the selected tenant, and hidden records return 404 | ADR 0002; REQUIREMENTS API-02, API-09 |
| A permission revoked before a command's check refuses the command; one revoked after the check waits for its commit | ADR 0012 amendment 3 |
| Disabled principals, suspended tenants and expired bindings are refused at the next request (not in flight) | ADR 0012 amendment 5 |
| A person cannot approve their own proposal; an approval covers exactly one payload digest | ADR 0010 |
| Decisions, events, audit and approvals cannot be rewritten through the runtime credential | ADR 0012 amendment 4 |
| The verification worker contacts only allowed origins at addresses it has checked, verifies TLS for the configured name, and accepts only answers bound to the request | ADR 0014 amendment 1 |
| Timestamps must name an instant; equivalent instants are one argument for idempotency | ADR 0015 |

Known gaps are listed under "Known limitations" in `docs/IMPLEMENTATION_STATUS.md`; finding them again is not a new
result, but showing a consequence they do not describe is.

### Reporting
For each finding: the capability used, the steps or a failing test, the claim it breaks and where that claim is
written. Record findings outside the author's control first (an issue, or a dated file under `docs/reviews/`, a folder that does not exist yet), then
the author responds. A finding is closed only by a test that fails before the fix and passes after it, or by a
correction to the claim.

## Track 2: evaluation labels

**Goal:** judge, without seeing the author's answers, whether each scenario's evidence supports the author's labels.

* **Instructions:** `evaluation/REVIEW-PROCEDURE.md` (who may review, the blind and sealed materials, the steps, the
  comparison tool). Follow it as written; this section only summarises.
* **Evidence access:** a reviewer receives only `blind/<case>/evidence.json` and `worksheet.csv` from the package
  built by `evaluation/export_review.py`. The author's labels (`sealed/`) and the pipeline's output are opened only
  after the reviewer's judgements are complete and their digest has been recorded.
* **Independent judgements:** each reviewer works alone and is recorded separately. Reviewers do not discuss cases
  with each other or with the author before sealing.
* **Disagreements:** recorded side by side by `evaluation/compare_review.py`. A label changes only through a new,
  documented version of `evaluation/cases.json` that names the reviewer record and who decided; keeping the author's
  label also needs a recorded reason.

**What this track cannot establish.** The scenarios have been visible to the author and the platform throughout
development. Even after review, the 16 cases (D1 to D6 development, H1 to H10 regression) remain **regression cases,
not an untouched held-out set** (evaluation/EXPOSURE.md). A held-out measure needs new scenarios written and labelled
by someone else, kept out of this repository until a frozen model route is evaluated once. No language model has been
evaluated at all.
