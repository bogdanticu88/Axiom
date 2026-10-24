# Image sources moved off `public.ecr.aws`, Dockerfile frontend pinned (verification run 30)

## Why

`public.ecr.aws` refused CI pulls of the pinned Python and PostgreSQL images with HTTP 429, "Data limit exceeded"
(runs 39980128200, 40009459095 and 40056023921, the last despite sequential pulls), and refused even read-only
manifest requests from a different network on 2026-10-24. This change moves those two images to a source that served
them. It does not guarantee that source stays available.

## Final image references (all pinned by digest)

| Image | Reference | Change |
|---|---|---|
| Dockerfile frontend | `mirror.gcr.io/docker/dockerfile:1.7@sha256:a57df69d…dda33e` | newly pinned; was `docker/dockerfile:1.7` from Docker Hub by tag |
| Python 3.13-slim | `mirror.gcr.io/library/python:3.13-slim@sha256:cf50a4f6…b850f` | registry moved; digest unchanged |
| PostgreSQL 16.15 | `mirror.gcr.io/library/postgres:16.15@sha256:a9025605…5c5690` | registry moved; digest unchanged |
| Node 22.20.0-slim | `mirror.gcr.io/library/node:22.20.0-slim@sha256:b21fe589…f5848e` | unchanged |
| SeaweedFS 4.48 | `mirror.gcr.io/chrislusf/seaweedfs:4.48@sha256:4e61d15f…c7872d` | unchanged |
| nginx 1.29.2-alpine | `mirror.gcr.io/library/nginx:1.29.2-alpine@sha256:61e01287…bfe22` | unchanged (TLS test) |
| Keycloak 26.4.2 | `quay.io/keycloak/keycloak:26.4.2@sha256:3617b09b…e1b9` | unchanged |

Both Dockerfiles (`Dockerfile`, `scripts/demo/app/Dockerfile`) carry the pinned frontend line; there are no other
syntax directives in the repository.

## Evidence

* `manifest-checks.txt`: for every reference above, the raw manifest fetched and hashed locally matches the pinned
  digest (7 of 7). Before pinning, the frontend's tag `1.7` resolved to the same digest on Docker Hub and on
  `mirror.gcr.io`. Docker Hub also served the Python, PostgreSQL, Node, SeaweedFS and nginx digests byte-identical.
  For the two moved images and the frontend, the linux/amd64 manifest was re-hashed and every config and layer blob
  was retrieved from `mirror.gcr.io`.
* `registry-unreachable-all-present.log`: Docker started with registry access cut, all images already present under
  their new references. The build and the whole smoke test passed (exit 0), so no pinned reference needs the registry
  once its image is present, including the pinned frontend.
* `registry-unreachable.log`: the same conditions with the frontend image removed. The sequential pull reported the
  registry error for the frontend and the test stopped with exit 1 before building; nothing was created.
* `normal.log`: normal registry access. The frontend was pulled once by digest, the rest were present, and every check
  passed.

All three local runs used images already on this machine and are cached runs, not cold installs. On GitHub the runner
starts with no images and nothing is cached between runs.

## Assumptions that remain

`mirror.gcr.io` is Google's cache of Docker Hub. It documents no quota (which is not the same as having none), keeps
only frequently requested images and does not promise to keep them. A pull it refuses, or of an image it no longer
holds, stops the smoke test with the registry's message. There is no retry, fallback, credential or cross-run cache.
