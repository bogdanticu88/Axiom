# GitHub Issues: first real integration test (plan and setup)

Status: **prepared, not run.** The GitHub Issues adapter is fixture-tested only. Nothing here has contacted the target
repository. Running the test needs the approvals listed at the end.

Test: `tests/integration/test_github_issues_optin.py` (opt-in, skipped by default). Manual workflow:
`.github/workflows/github-issues-optin.yml`. Target: a disposable private repository, synthetic data only, no model
calls, no client data.

## What the adapter does (current main)

* `POST /repos/{owner}/{repo}/issues` with `title`, `body`, `labels`; the operation key is written as a marker line
  `axiom-operation: <key>` in the body. 201 is success; 401, 404, 410, 422 are permanent refusals; 403, 429 and 5xx
  are treated as an unknown outcome, because GitHub uses 403 and 429 for rate limits too.
* Lookup: `GET /repos/{owner}/{repo}/issues?state=all&since=<72 h ago>`, up to 5 pages, for the marker. A hit is
  adopted; a miss is never treated as proof that nothing was created. The adapter declares no deduplication (GitHub
  offers no idempotency key), so after an uncertain create a miss parks the job for an operator.
* Verification: `GET /repos/{owner}/{repo}/issues/{number}` and the marker check.
* API version header `2022-11-28`, which GitHub supports until 10 March 2028 and still uses by default
  ([API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)).
* Change in this PR: if the credential cannot be read when the create is built, no request is sent, and the attempt
  is now recorded as definitely not applied (retried), instead of an unknown outcome that parks for an operator. On
  main that case left the intent `unknown` with zero requests sent
  (`test_github_credential_unreadable_at_create_is_not_an_unknown_outcome`).

## Credential and minimum access

A **fine-grained personal access token** restricted to the one repository:

| Setting | Value | Why |
|---|---|---|
| Resource owner | your account (`bogdanticu88`) | the repository's owner |
| Repository access | Only select repositories: the test repository | nothing else is reachable |
| Repository permission: Issues | **Read and write** | create, list, get, close ([docs](https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#create-an-issue)) |
| Repository permission: Metadata | Read-only (the form adds it) | read the repository's `private` and `has_issues` flags |
| Everything else | No access | |
| Expiration | 7 days | the test takes minutes |

The endpoint documentation names "Issues" (write) for creating and (read) for listing and reading issues. It does not
say on those pages that Metadata is mandatory; check what the token form shows. Labels need push access and are
otherwise dropped silently; the test sends no labels. Creating issues triggers notifications and counts toward
GitHub's secondary limit for content creation (80 a minute, 500 an hour,
[rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28)).
The normal run creates 4. Issues cannot be deleted through the REST API; in a personal-account repository only the
owner can delete them, in the web interface
([deleting an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/administering-issues/deleting-an-issue)).

Secret handling: the platform reads the token only through `secretref:file/<absolute path>`, the production path
(`AXIOM_SECRET_FILE_DIRS` names the directory; the file must be 0600). It is never placed in configuration, an
environment variable given to the platform, the database or a log. The test checks that the token value appears in no
log record and no row it wrote; the workflow checks its log before uploading it.

## Scenarios

The normal run has four scenarios that create an issue, two that create none, and creates **4 issues** in total.
Requests are the platform's, through the recording transport. The test's own reads (the precondition check, the
marker search used for assertions) and the final `PATCH` that closes each created issue come on top.

| # | Scenario | Issues | Platform requests expected | How uncertainty is induced |
|---|---|---|---|---|
| 1 | One approved action creates one issue; reference `owner/repo#N` stored, verified, use consumed | 1 | `GET` list (lookup, miss), `POST` (201), `GET` issue (verify) | none |
| 2 | Replay after a lost response: the next attempt looks the issue up instead of creating | 1 | `GET` list, `POST` (201, response discarded); then `GET` list (hit) and `GET` issue. If GitHub's list does not show the issue yet: the job parks, the operator adopts, `GET` issue | the `POST` is sent once and its response discarded locally |
| 3 | Uncertain create the lookup cannot see: parks, operator adopts, read back | 1 | `GET` list, `POST` (201, discarded); `GET` list (issue hidden: miss) and park; after adoption `GET` issue | lost response, and the new issue hidden from the list the adapter reads (stale index) |
| 5 | Cancellation and takeover after the create is authorized: use held, late success recorded, operator adopts, approval exhausted | 1 | `GET` list; `POST` held before it leaves; worker B's claim (no requests); then the one `POST` (201) and `GET` issue | worker A paused before sending; its lease expired by the database clock |
| 4 | Cancellation before dispatch: use returned after the witness check | 0 | `GET` list (held, then sent) | worker A paused at its lookup |
| 6 | Unavailable credential | 0 | none | the secret file does not exist |

Refusal runs, separately: `readonly` (token edited to Issues read-only) expects `GET` list then one refused `POST`
(403) and a park; `revoked` (token deleted) expects one refused `GET` (401) and no `POST`.

**Observed directly from GitHub:** create and its response, the issue list with `since` and whether it already shows a
just-created issue (scenario 2 records which branch it took), reading an issue back, closing, the permission refusal
and the revoked token. **Simulated locally:** the lost response, the stale index, the paused worker, the lease expiry,
the missing secret file. No simulation sends a request of its own: a lost response discards the answer to the one
request that was sent, and the stale index edits the list the adapter receives.

**Timeouts and failures cannot send extra creates.** The platform never sends a second create for an operation once
the first may have reached GitHub: the adapter declares no deduplication, so after an uncertain outcome the gate only
looks up or parks (asserted in every scenario: one `POST`). A request the test holds is sent only when the test calls
`send()`; if an assertion fails it is withdrawn, and if the 60-second wait passes it is withdrawn too. A withdrawn
request is refused locally as a connection failure and never reaches GitHub. Every request, the platform's and the
test's, may go only to `api.github.com`, and no redirect is followed (`tests/unit/test_github_issues_redirects.py`), so
the token cannot be forwarded to another host. Creation is not exactly-once: the test checks the platform sends at
most one create per operation.

**What the secret checks cover, and what they do not.** Each test checks that the exact token string appears in no log
record captured from the process and in no row it wrote to `job_events`, `action_executions` or `effect_intents`; the
checks compare booleans and counts, so a failure does not print the token. The workflow searches the whole test log
for the exact string before uploading it, and GitHub Actions masks registered secrets in the job's console log. These
are exact-match checks only: they do not detect an encoded, split or partial copy, output written outside the
captured log (a core dump, another process), or other tables. The recording transport keeps method, path and status;
a refusal keeps GitHub's error message and the `x-accepted-github-permissions` header; issue bodies and other response
content are not logged. A permanent refusal's error text (up to 300 characters of GitHub's JSON) is kept in the job's
`last_error`, as for every adapter.

## Running it

Two ways; both keep the token out of chat and out of this workspace. **The protected environment, its secret and its
variable live in the Axiom repository (`bogdanticu88/Axiom`), which runs the workflow. The target repository
(`bogdanticu88/axiom-integration-test`) needs no settings beyond being private with Issues enabled.**

**A. GitHub Actions (recommended).** The workflow must be on `main` to be dispatched, so this needs PR 10 merged.

1. Target repository `bogdanticu88/axiom-integration-test`: make sure it is **private**, has **Issues enabled**, has no
   collaborators, and holds nothing you want to keep. Change nothing else there.
2. Axiom: Settings, Environments, New environment, name `github-issues-integration`.
   * Deployment protection rules: tick **Required reviewers** and add yourself. **Leave "Prevent self-reviews"
     unticked**: you will dispatch the run and approve it yourself, which that option would forbid. As the only
     reviewer, approving is a deliberate second step; the run waits until you do.
   * Deployment branches and tags: **Selected branches and tags**, add `main`.
   * Environment variables: `AXIOM_TEST_GITHUB_REPO` = `bogdanticu88/axiom-integration-test`.
3. Create the token (Settings of your account, Developer settings, Fine-grained tokens, Generate new token) with the
   settings in the table above, expiring in 7 days.
4. Axiom, the same environment, Environment secrets: add `AXIOM_TEST_GITHUB_TOKEN` and paste the token there (only
   there).
5. Axiom, Actions, `github-issues-optin`, Run workflow, branch `main`, with:
   * `mode`: `normal`
   * `approved_repo`: `bogdanticu88/axiom-integration-test`
   * `expected_sha`: the full hash of the main commit you reviewed (`git rev-parse origin/main`).

   The run fails before checkout if the branch, the commit or the repository differ.
6. The run waits for review: open it, check the inputs, Review deployments, tick the environment, Approve.
7. The log is attached to the run as an artifact (uploaded only if the token check passed).

**B. Your own machine** (PostgreSQL 16 server binaries and `uv`; Linux or macOS):

```sh
git clone https://github.com/bogdanticu88/Axiom.git && cd Axiom && git checkout main
uv sync --frozen && scripts/dev/test-db.sh start
mkdir -p ~/.axiom-secrets && chmod 700 ~/.axiom-secrets
( umask 077; read -rs -p "token: " T && printf '%s' "$T" > ~/.axiom-secrets/github-test-token; unset T; echo )
set -a && . ./.env.test && set +a
AXIOM_TEST_GITHUB_ISSUES=1 AXIOM_TEST_GITHUB_REPO=bogdanticu88/axiom-integration-test \
AXIOM_TEST_GITHUB_APPROVED_REPO=bogdanticu88/axiom-integration-test \
AXIOM_TEST_GITHUB_TOKEN_FILE="$HOME/.axiom-secrets/github-test-token" AXIOM_TEST_GITHUB_MODE=normal \
  uv run --frozen pytest -rA -s -p no:cacheprovider tests/integration/test_github_issues_optin.py | tee optin.log
```

`read -s` keeps the token off the screen and out of shell history. The test leaves the file in place (the refusal
runs need it); delete it at the end.

**Then, optional refusal runs:** edit the token to Issues: Read-only and run mode `readonly`; then delete the token and
run mode `revoked`.

**Cleanup:** delete the 4 closed issues (or the whole target repository), delete the token, delete the environment
secret in Axiom, and with option B remove `~/.axiom-secrets/`.

## Workflow controls

* Trigger: `workflow_dispatch` only. No `push`, `pull_request` or `pull_request_target` trigger, so no pull request,
  fork or branch push runs it, and dispatching needs write access to Axiom.
* Revision: the job runs only on `refs/heads/main` and only if the run's commit equals `expected_sha`; it checks out
  that commit. The environment also admits only `main`.
* Secret: an environment secret, released to the job only after a required reviewer approves; written to a 0600 file
  under the runner's temporary directory and removed by an always-run step, including when an earlier step failed.
  GitHub-hosted runners are discarded after the job.
* Token permissions: the workflow's `GITHUB_TOKEN` has `contents: read` only, and checkout does not persist it.
* Pinned: actions by full commit hash (the same as `ci.yml`, verified by `scripts/ci/check-action-pins.sh`), uv by
  version, Python packages by `uv.lock`. Not pinned: the Ubuntu `postgresql-16` package and the runner image, as in
  `ci.yml`.
* Concurrency: one group, not cancelled in progress, so two dispatches never run at once (GitHub keeps at most one
  waiting and replaces an older waiting run). Each run's issues carry their own operation markers, and cleanup closes
  only the issues that run created.

## Rehearsal (part of ordinary CI)

`tests/integration/test_github_optin_rehearsal.py` runs the opt-in module in child processes with
`tests/integration/github_optin_rehearsal.py`, which replaces real HTTP before any fixture exists and points the test
at the non-routable `api.github.test.invalid` and the example repository `example-owner/axiom-optin-rehearsal`:
without opt-in all 8 tests skip and nothing is sent; normal, readonly and revoked pass with zero network attempts (4
fake issues created and closed); an unapproved target is refused before any request; and a control that installs the
fake too late, the mistake made during the first manual rehearsal (which sent 6 requests with a placeholder token to
an unrelated repository on `api.github.com`), is caught by the network block. This checks the test and its isolation,
not GitHub.
