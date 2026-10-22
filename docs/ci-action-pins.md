# GitHub Actions pins

`.github/workflows/ci.yml` references every action by a **full 40-character commit hash**, followed by a comment
naming the release tag it was resolved from (ADR 0007). Tags and branches are mutable; a hash is not.

| Action | Tag | Commit | Tag commit date | Resolved |
|---|---|---|---|---|
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 | 2026-07-17 | 2026-10-22 |
| actions/setup-python | v7.0.0 | 5fda3b95a4ea91299a34e894583c3862153e4b97 | 2026-07-19 | 2026-10-22 |
| actions/upload-artifact | v7.0.2 | cf430e030ddbb5b0abf93d22962f4752f3646cd9 | 2026-10-07 | 2026-10-22 |

How they were chosen: the newest release of each action whose commit is at least 14 days old (the same cooldown as
the Python lock, ADR 0007). `actions/setup-python` v7.1.0 was one day old and was not used. The inputs the workflow
uses (`python-version`, `name`, `path`, `retention-days`) were checked in each pinned commit's `action.yml`; all three
run on `node24`.

How they were verified: `git ls-remote https://github.com/<owner>/<repo>.git refs/tags/<tag>` against the official
repositories (HTTPS through this environment's proxy), then a shallow fetch of each tag to read its commit date and
`action.yml`. `scripts/ci/check-action-pins.sh` repeats the hash check and fails on any unpinned `uses:` line; it runs
as a stage of `scripts/ci/run.sh`.

## Updating a pin
1. Pick the release: `git ls-remote --tags https://github.com/<owner>/<repo>.git` and read its release notes in the
   official repository. Prefer a release at least 14 days old unless a security fix requires otherwise (record why).
2. Resolve the commit: `git ls-remote https://github.com/<owner>/<repo>.git "refs/tags/<tag>" "refs/tags/<tag>^{}"`
   (for annotated tags use the `^{}` line, which is the commit).
3. Review the change between the old and new commit (inputs in `action.yml`, runtime, permissions it needs).
4. Edit the `uses:` line to `owner/repo@<40-hex-commit> # <tag>` and update the table above.
5. Run `scripts/ci/check-action-pins.sh`, then `scripts/ci/run.sh`.

Hosted CI remains unverified: the workflow has never run on GitHub because no repository remote is authorised.
