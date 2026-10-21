# Fixture provenance

Every fixture is either output of a real tool run on a public artefact, or synthetic data written for this project.
None contains customer, corporate or personal data. Synthetic fixtures use `.invalid` domains, made-up UUIDs and
`CVE-2099-*` identifiers so they cannot be mistaken for real findings.

| File | Kind | Origin | Licence / notes |
|---|---|---|---|
| trivy/debian-bullseye-20230612-slim.subset.json | **real tool output, trimmed** | Trivy 0.76.1 (`mirror.gcr.io/aquasec/trivy:latest`), DB `mirror.gcr.io/aquasec/trivy-db:2` updated 2026-10-21T19:18Z. Command: `trivy image --quiet --skip-db-update --input target.tar --format json` on `public.ecr.aws/docker/library/debian:bullseye-20230612-slim` (`sha256:924df86f8aad741a0134b2de7d8e70c5c6863f839caadef62609c1be1340daf5`), run 2026-10-21 22:04Z. Original: 464 vulnerabilities; kept 30 (4 sharing a CVE across packages, then the first 26 by package/CVE). `ArtifactName`, `Target` and `RepoDigests` were set to the pulled image reference because the scan used a tarball input. | Trivy is Apache-2.0. Advisory text originates from upstream sources (e.g. Debian security tracker, NVD) as aggregated in trivy-db |
| sarif/trivy-debian-bullseye.subset.sarif | **real tool output, trimmed** | Same scan, `--format sarif`; first 30 results and their 29 rules, `ruleIndex` renumbered. No `versionControlProvenance` (container scan). | as above |
| sarif/synthetic-code-scanning.sarif | **synthetic** | Written against the SARIF 2.1.0 schema (schemastore) to cover features absent from the Trivy SARIF: version-control provenance, `originalUriBaseIds`, fingerprints and partial fingerprints, suppressions, `kind: pass`, baseline state, a prompt-injection string in a message, and two invalid results (bad `ruleIndex`, invalid `level`). | project-authored |
| tenable/synthetic-vulns-chunk-1.json | **synthetic** | Shape follows Tenable's documented export chunk fields (developer.tenable.com, "Download vulnerabilities chunk" and "Request vulnerability export", fetched 2026-10-22). Not real Tenable output; not validated against a live Tenable instance. Includes: two asset UUIDs sharing hostname and IP (identity conflict), a FIXED finding, a REOPENED finding, and a record without `asset.uuid` (quarantine). | project-authored |
| azure/synthetic-arg-page-1.json, -2.json | **synthetic** | Shape follows the Azure Resource Graph Resources REST API (api-version 2024-04-01) response, including `$skipToken` paging. Not real Azure output. | project-authored |

Rules: never add customer or corporate data; record origin, tool version, command and licence for every new fixture;
mark synthetic fixtures as synthetic; keep real-tool fixtures small enough to review.
