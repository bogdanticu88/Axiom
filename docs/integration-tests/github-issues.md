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

| # | Scenario | Issues created | Provider behaviour tested directly | Simulated locally |
|---|---|---|---|---|
| 1 | One approved action creates one issue; the reference `owner/repo#N` is stored, verified, use consumed | 1 | create, lookup miss before it, read back | nothing |
| 2 | Lost response, then replay: the next attempt looks the issue up instead of creating | 1 | whether the list already shows a just-created issue (recorded either way) | the response to the one create is discarded |
| 3 | Uncertain create the lookup cannot see: the job parks, the operator adopts, verification reads it back | 1 | read back of the adopted issue | lost response; the issue hidden from the list (stale index) |
| 4 | Cancellation before dispatch: the use is returned after the witness check | 0 | the lookup | worker paused at its lookup |
| 5 | Cancellation and worker takeover after the create is authorized: the use stays reserved; the late success is recorded; the operator adopts; the approval cannot run again | 1 | the create, sent once, after the takeover | worker paused before its request leaves; lease expiry |
| 6 | Unavailable credential: nothing is sent | 0 | none (GitHub not contacted) | the secret file does not exist |
| 7 | `readonly` run: the create is refused (403 expected); the job parks, the operator abandons, the use stays consumed; the refusal's status and accepted-permissions header are recorded | 0 | permission refusal | nothing (token edited to read-only) |
| 8 | `revoked` run: the lookup is refused (401 expected); no create is attempted | 0 | revoked token | nothing (token deleted) |

Normal run: **4 issues**, each created by exactly one request; the test closes them at the end (`not_planned`) and
prints their numbers. No scenario sends a second create for the same operation, and none induces duplicate requests.
The test checks that the platform sends at most one create per operation; it does not make creation exactly-once.

## Running it

Two ways; both keep the token out of chat and out of this workspace.

**A. GitHub Actions (recommended).** Needs this PR merged (the workflow must be on the default branch to be
dispatched).

1. Make sure `bogdanticu88/axiom-integration-test` is **private**, has **Issues enabled**, no collaborators, and holds
   nothing you want to keep.
2. In `bogdanticu88/Axiom`: Settings, Environments, New environment `github-issues-integration`. Add yourself as a
   **required reviewer**; under deployment branches allow `main` only.
3. In that environment add the variable `AXIOM_TEST_GITHUB_REPO` = `bogdanticu88/axiom-integration-test`.
4. Create the token (table above): Settings, Developer settings, Fine-grained tokens, Generate new token.
5. Add it in that environment as the secret `AXIOM_TEST_GITHUB_TOKEN` (pasted into GitHub's form only).
6. Actions, `github-issues-optin`, Run workflow, mode `normal`; approve the environment when asked.
7. The log is attached to the run as an artifact.

**B. Your own machine** (PostgreSQL 16 server binaries and `uv` installed; Linux or macOS):

```sh
git clone https://github.com/bogdanticu88/Axiom.git && cd Axiom && git checkout <this PR's branch or main>
uv sync --frozen && scripts/dev/test-db.sh start
mkdir -p ~/.axiom-secrets && chmod 700 ~/.axiom-secrets
( umask 077; read -rs -p "token: " T && printf '%s' "$T" > ~/.axiom-secrets/github-test-token; unset T; echo )
set -a && . ./.env.test && set +a
AXIOM_TEST_GITHUB_ISSUES=1 AXIOM_TEST_GITHUB_REPO=bogdanticu88/axiom-integration-test \
AXIOM_TEST_GITHUB_TOKEN_FILE="$HOME/.axiom-secrets/github-test-token" AXIOM_TEST_GITHUB_MODE=normal \
  uv run --frozen pytest -rA -s -p no:cacheprovider tests/integration/test_github_issues_optin.py | tee optin.log
```

`read -s` keeps the token off the screen and out of shell history.

**Then, optional refusal runs:** edit the token to Issues: Read-only and run mode `readonly`; then delete the token and
run mode `revoked` (with option B, keep the file until that run, then delete it).

**Cleanup:** delete the 4 closed issues (or the whole repository), delete the token (Settings, Developer settings,
Fine-grained tokens, Delete), delete the environment secret, and with option B remove `~/.axiom-secrets/`.

## Rehearsal

The test logic was rehearsed against the local GitHub fake with a scratch plugin that blocks real network access:
normal 6 passed (4 fake issues, closed), readonly 1 passed, revoked 1 passed. That checks the test, not GitHub.
