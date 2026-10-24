# ADR 0007: Dependency pinning and supply chain

Status: accepted (2026-10-22)

* Python dependencies are declared in `pyproject.toml` and locked in `uv.lock`. Resolution uses
  `exclude-newer = 2026-10-14T00:00:00Z`, a cooldown that excludes releases newer than about a week at lock time.
  Upgrades are deliberate: `uv lock --upgrade` with a new cutoff, then the full verification.
* Locked versions at this checkpoint include fastapi 0.143.0, starlette 1.8.0, uvicorn 0.54.0, pydantic 2.14.1,
  psycopg 3.3.6, psycopg-pool 3.3.3, pyjwt 2.15.1, cryptography 50.0.2, boto3 1.43.113, pytest 9.1.1.
* Container images are pinned by digest: PostgreSQL 16.15
  (`sha256:a902560563d3a5661228585f53474c5065e7f273b21ffd77e555a8b5682c5690`), SeaweedFS 4.48
  (`sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d`), Python 3.13-slim base
  (`sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f`). Docker Hub was rate-limited here, so
  images came from `public.ecr.aws` and `mirror.gcr.io`; digests are registry-independent.
* **Amendment (2026-10-24, verification run 30).** `public.ecr.aws` refused CI pulls of the Python and PostgreSQL
  images with "Data limit exceeded", so both now come from `mirror.gcr.io/library` with the same digests. Before the
  move, the manifests served there were hashed and found byte-identical to the pinned digests, and every linux/amd64
  layer was retrieved. `mirror.gcr.io` is Google's cache of Docker Hub: it documents no quota but keeps only
  frequently requested images, with no guarantee of retention. This moves away from a source that was refusing pulls;
  it does not guarantee that the new one stays available.
* The Dockerfile frontend is pinned by digest (amendment of 2026-10-24) in both Dockerfiles:
  `mirror.gcr.io/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`,
  the digest `docker/dockerfile:1.7` resolved to on Docker Hub and on `mirror.gcr.io` when it was pinned.
* Image signing, SBOM generation and vulnerability scanning of our own images are planned (DEP-07, DEP-08).
* The Temporal CLI in the experiment is fetched as "latest" and its checksum was not verified against a published
  value; acceptable for an experiment only.
