# Sequential pinned image pulls in the Compose smoke test

Two local runs of `scripts/verify/compose-smoke.sh` after the pre-pull was added (verification run 29). Each line is
prefixed by the seconds since the run started, added by the harness, not by the script.

| Log | Conditions | Exit status | What it shows |
|---|---|---|---|
| `registry-unreachable.log` | Docker started with an unreachable proxy, so no registry could be reached; the SeaweedFS image removed beforehand | 1 | the PostgreSQL image found locally, then the SeaweedFS pull failing with its output, then `SMOKE FAIL: image pull`; no container created |
| `normal.log` | `BUILD=1`, normal registry access; four of the five pinned images already on this machine, SeaweedFS absent | 0 | four images present, SeaweedFS pulled once (6 s), image built, every check passed including the browser check |

Neither run is a cold install: the machine already held most images. On GitHub the runner starts empty and nothing is
cached between runs, so there every image is pulled once.

A separate check with registry access cut off: a build whose `FROM` names the pinned Python image by digest succeeded
when that image was already present, so a pre-pulled base image is not requested again by the build; a pull of an
absent image failed, confirming the registry was unreachable. A build with the Dockerfile's `# syntax=docker/dockerfile:1.7`
line failed in the same conditions, because that image is resolved by tag from Docker Hub on every build. It is not
pinned by digest, and that is unchanged.
