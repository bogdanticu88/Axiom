# Remediation demonstration

This walks one vulnerability from a real scan to a verified, human-approved closure, on one machine, without a
language model, a hosted tracker or any external service once the images and the scanner database are cached. It
also shows that the same verification refuses to pass two deployments that were not fixed.

## What runs, and what is real

| Part | What it is | Label in `results.json` |
|---|---|---|
| Two demo services, `orders-api` and `reports-api` | A small Python web app (`scripts/demo/app`) pinned to Jinja2 3.1.2, which has published advisories. Built locally, pushed to a registry container on `localhost:5000`, run as containers | `lab` |
| Scanner | Trivy 0.76.1 (image pinned by digest), real scans of the running images. The database is downloaded once and never updated during a run | `scanner` |
| Axiom | API, database, job worker, policies, verification worker and analyst UI from this repository, against the test PostgreSQL and a local Keycloak; the UI is driven in Chromium | `real` |
| Investigation model | The **deterministic fake model**. No language model is called. The UI labels the route "FAKE MODEL" and the run "Fake model (not a language model)" | `fake` |
| Ticket tracker | The in-process Jira-style **fake**. No tracker is contacted | `fake` |
| Check service | `scripts/demo/check_service.py`, a local HTTPS service implementing `axiom-check/2` by rescanning the running container with Trivy | see below |
| People's inputs | Business context, claim reviews, the redeployed digest, the change reports | `manual` |

## Prerequisites

* Linux or macOS with Docker (daemon running, about 3 GB free for images) and the Docker CLI on `PATH`.
* Python 3.13 with the project environment (`uv sync`, which creates `.venv`), Node 22 to build the analyst UI if
  `frontend/dist` is missing, and Playwright's Chromium (`.venv/bin/playwright install chromium` if not present).
* The test PostgreSQL that `scripts/dev/test-db.sh start` sets up, and the local Keycloak image
  (`quay.io/keycloak/keycloak:26.4.2`) that the UI tests start.
* Free local ports: 5000 (registry), 18081 and 18082 (demo services), 18443 (check service), plus the ports the UI
  tests use for Keycloak and the API.
* Network access on the first run only: the base image `mirror.gcr.io/library/python:3.13-slim` and the
  Dockerfile frontend `mirror.gcr.io/docker/dockerfile:1.7` (both pinned by digest), the registry and Trivy images
  from `mirror.gcr.io`, two wheels from PyPI (hash-pinned), and the Trivy vulnerability
  database (`mirror.gcr.io/aquasec/trivy-db:2`). Behind a TLS-intercepting proxy, set `BUILD_CA` to that proxy's CA
  bundle; otherwise leave it unset.

## Reproduce

```
scripts/demo/run.sh demo-out            # about two minutes once images are cached
python3 scripts/demo/lab.py down        # remove the demo containers afterwards
```

`run.sh` starts the test database, runs `lab.py up` (registry, Trivy database, both services built and deployed
vulnerable), then runs `tests/integration/test_demo_remediation.py` with `AXIOM_DEMO=1`. Without that variable the
test is skipped, so CI does not need Docker images or the scanner. Output in `demo-out/`:

* `results.json`: the tested commit, digests, outcomes and every labelled step
* `scans/*.json`: the raw Trivy reports that were imported
* `case-history.json`, `evidence-package.json`: the exported history of the closed case
* `screenshots/`: the UI at the approval, verification, closure and the two controls
* `check-service.log`, `pytest.log`, `lab.json` (Trivy database metadata and the deployed digests)

## The scanner database is a moving dependency

The outcome depends on the Trivy database present in the `axiom-demo-trivy-cache` volume. `lab.py up` downloads it
when the cache is empty or past its `NextUpdate` time, and scans never update it. The database changes daily, so the
same images can produce different findings on different days:

* if a new advisory is published for Jinja2 3.1.6, the remediated deployment no longer verifies and the
  demonstration fails instead of passing;
* if the selected advisories were withdrawn or renamed, the test cannot find its cases and fails;
* the count of operating-system findings in the base image changes freely and does not affect the outcome.

Image builds are not bit-for-bit reproducible either (timestamps), so digests differ between runs; each run records
its own. To interpret a past run, compare against the run's `lab.json` and raw scans, not against a fresh scan.

## Recorded run

The run at commit `185af5b98fcb3eac46b52c736ffd2ecd58702877` (verification run 21; records in
`docs/verification/2026-10-22-after-checkpoint8/demo/`):

| Item | Value |
|---|---|
| Scanner | Trivy 0.76.1, image `mirror.gcr.io/aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` |
| Database | schema version 2, `UpdatedAt` 2026-10-22T19:14:47Z, `NextUpdate` 2026-10-23T19:14:47Z, `DownloadedAt` 2026-10-22T20:15:30Z |
| Scan times | 2026-10-22T20:45:09Z (both services) |
| Base OS reported | Debian 13.7; 176 findings per image in total |
| Jinja2 3.1.2 findings (both images, source GHSA, severity MEDIUM) | CVE-2024-22195 (fixed 3.1.3), CVE-2024-34064 (3.1.4), CVE-2024-56201 (3.1.5), CVE-2024-56326 (3.1.5), CVE-2025-27516 (3.1.6) |
| Demonstrated case | CVE-2024-22195 on `pkg:pypi/jinja2@3.1.2`, orders-api |
| Control A | CVE-2024-22195 on reports-api, change reported against the unchanged deployment: `failed`, `condition_present` |
| Control B | CVE-2024-34064 on reports-api, fixed image pushed but not deployed: `inconclusive`, `different_deployment` |
| Digests | orders-api before `sha256:6fac686f…`, after `sha256:014fada1…`; reports-api `sha256:1b656a1c…` throughout; full values in `results.json` |

Later runs with the same scanner image and database: `b2d2ae1` (run 22) and `a05c01f` (2026-10-23, records in
`docs/verification/2026-10-23-demo-main/`, screenshots in `docs/demo/`). Each reached the same outcomes: the
demonstrated case passed and was closed, control A failed (`condition_present`), control B was inconclusive
(`different_deployment`). Digests differ per run.

## The steps

1. **Scan.** Trivy scans the image each service container is running, by registry digest.
2. **Import and bind.** Both reports go through `POST /imports` and the job worker. The test checks that each
   finding's asset version carries the digest Docker reports for the running container.
3. **Investigate and prioritise.** A run through the model gateway with the deterministic fake; a second analyst
   reviews its claims; the assessment cites the run; priority comes from a published policy.
4. **Approve and remediate.** An analyst proposes a ticket. Bob approves it **in the browser**; the proposer cannot.
   The ticket goes to the tracker fake through the effect gate. The lab then rebuilds `orders-api` with Jinja2 3.1.6
   and replaces the running container, and an analyst records the new digest as an asset version.
5. **Verify.** The owner reports the change. The verification worker, with its own identity, sends the case's
   condition (CVE and package) to the check service and records the outcome.
6. **Close and export.** Alice closes the case **in the browser** with the worker's run. The case history and the
   auditor's evidence package are exported.

Negative controls use the same connection, worker and check service on `reports-api`, which is never changed:

* **A, unchanged deployment.** A change is reported against the deployment that is still running. The service
  finds the CVE: `failed`, rule `condition_present`, and the case goes back to remediation.
* **B, fix built but not deployed.** A fixed image is pushed and reported, but the old container keeps running. The
  service reports the running digest, which is not the reported one: `inconclusive`, rule `different_deployment`.

## What the verification checks

Axiom sends the job id, a fresh nonce, the asset, the reported deployment digest and the case's conditions (here
`CVE-2024-22195` on `pkg:pypi/jinja2@3.1.2`). The check service:

1. asks Docker which image the asset's demo container is running and resolves its registry digest;
2. scans that image with Trivy, offline;
3. reports each condition `present` when the scan lists the same vulnerability on the same package (any version),
   `absent` when the scan completed without it, `error` when the scan failed; plus the examined digest and time.

Axiom then accepts a pass only when the response echoes the job id, nonce and asset, names a digest equal to the
reported one, was observed after the change was reported and within the configured age, covers every condition
completely, and reports every condition absent. It stores the response as evidence and records who and what was
asked (origin, connected address, request and response digests).

It does **not** check whether the vulnerable code is reachable, other replicas or hosts, code loaded at run time
outside the image, or whether Trivy's database knows about every advisory for the package.

## Who controls the endpoint, and what a compromised one could claim

In this demonstration the person running it controls everything: the check service is a child process of the test,
uses the local Docker daemon (equivalent to root on the host), and holds a throwaway TLS key and bearer token.

In a deployment, three parties decide what is believed:

* whoever holds `connection.configure` on the project chooses the endpoint URL and its bearer token reference;
* whoever sets the worker's environment (`AXIOM_VERIFICATION_DESTINATIONS`, `AXIOM_VERIFICATION_NETWORKS`) decides
  which origins and addresses may be contacted at all;
* whoever operates the check service, its host, its Docker or orchestrator access and its scanner database decides
  what it answers. TLS proves Axiom reached the configured name; it says nothing about the honesty of the answer.

A compromised or dishonest endpoint can make Axiom record a **false pass**: it can say `absent` for a condition that
is present, claim it examined the reported digest when it examined something else or nothing, give any observation
time inside the window, and claim complete coverage. Every field Axiom checks for binding (job id, nonce, asset,
digest) is either in the request or chosen by the endpoint, so it can always satisfy them. It can equally report
false failures or keep cases inconclusive. It also learns what it is asked: asset names, digests and CVEs.

It cannot replay an earlier answer to a new request (the nonce), close a case (a person must, and the person who
reported the change cannot verify it), act for another tenant, or change anything already recorded. Nothing signs
the endpoint's claims; the stored response lets a later reviewer see what was asserted, not whether it was true.

## Limits of this demonstration

* One machine, one tenant, two services, one dependency upgrade. Nothing here measures scale or usefulness.
* The tracker and the investigation model are fakes; the redeployed digest is typed in by a person (as an API call),
  because Axiom has no deployment integration.
* The check service is demonstration code. It is not packaged, hardened or supported, and it trusts Docker's answer
  about which image a container runs.
* The UI's support badge for the verification connection still reads "fixture-tested": the check service exists only
  in this repository and only for this demonstration.
