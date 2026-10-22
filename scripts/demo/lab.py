"""Local lab for the remediation demonstration: a registry, two demo services, and Trivy.

Everything runs on this machine through the Docker CLI. Nothing is pushed anywhere except the registry container this
script starts on 127.0.0.1:5000. Commands:

    python scripts/demo/lab.py up            registry, Trivy database, both services built and deployed vulnerable
    python scripts/demo/lab.py build SERVICE VARIANT     build and push; prints the registry digest
    python scripts/demo/lab.py deploy SERVICE DIGEST     replace the running container with that image
    python scripts/demo/lab.py running SERVICE           digest of the image the container is running
    python scripts/demo/lab.py scan REF OUT              real Trivy scan of REF, JSON written to OUT
    python scripts/demo/lab.py down                      remove containers (the Trivy cache volume is kept)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY = "localhost:5000"
REGISTRY_IMAGE = "mirror.gcr.io/library/registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
TRIVY_IMAGE = "mirror.gcr.io/aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
TRIVY_DB = "mirror.gcr.io/aquasec/trivy-db:2"
CACHE_VOLUME = "axiom-demo-trivy-cache"
SERVICES = {"orders-api": 18081, "reports-api": 18082}
VARIANTS = {"vulnerable": "requirements-vulnerable.txt", "fixed": "requirements-fixed.txt"}


def sh(*args: str, capture: bool = True, check: bool = True) -> str:
    r = subprocess.run(args, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(args)}\n{r.stdout or ''}{r.stderr or ''}")
    return (r.stdout or "").strip()


def repository(service: str) -> str:
    return f"{REGISTRY}/axiom-demo/{service}"


def container(service: str) -> str:
    return f"axiom-demo-{service}"


def registry_up() -> None:
    if sh("docker", "ps", "-q", "-f", "name=^axiom-demo-registry$"):
        return
    sh("docker", "rm", "-f", "axiom-demo-registry", check=False)
    sh("docker", "run", "-d", "--name", "axiom-demo-registry", "-p", "127.0.0.1:5000:5000", REGISTRY_IMAGE)


def extra_ca() -> list[str]:
    """Behind a TLS-intercepting proxy, BUILD_CA names the CA bundle Trivy should trust for the database download."""
    ca = os.environ.get("BUILD_CA")
    return ["-v", f"{ca}:/etc/axiom-demo-ca.pem:ro", "-e", "SSL_CERT_FILE=/etc/axiom-demo-ca.pem"] if ca else []


def trivy_db() -> dict:
    """Download the vulnerability database once into the cache volume; later scans never update it."""
    sh("docker", "run", "--rm", *extra_ca(), "-v", f"{CACHE_VOLUME}:/root/.cache", TRIVY_IMAGE, "image", "--quiet",
       "--download-db-only", "--db-repository", TRIVY_DB)
    meta = sh("docker", "run", "--rm", "-v", f"{CACHE_VOLUME}:/c", "--entrypoint", "cat", TRIVY_IMAGE,
              "/c/trivy/db/metadata.json")
    return json.loads(meta)


def build(service: str, variant: str) -> str:
    ref = f"{repository(service)}:{variant}"
    args = ["docker", "build", "-q", "-t", ref, "--build-arg", f"REQUIREMENTS={VARIANTS[variant]}",
            "--label", f"org.opencontainers.image.title={service}"]
    if os.environ.get("BUILD_CA"):
        args += ["--secret", f"id=ca,src={os.environ['BUILD_CA']}"]
    sh(*args, str(HERE / "app"))
    sh("docker", "push", "-q", ref)
    return registry_digest(ref, service)


def registry_digest(ref: str, service: str) -> str:
    digests = json.loads(sh("docker", "image", "inspect", ref, "--format", "{{json .RepoDigests}}"))
    mine = [d for d in digests if d.startswith(repository(service) + "@")]
    if not mine:
        raise SystemExit(f"{ref} has no digest in {REGISTRY}")
    return mine[0].split("@", 1)[1]


def deploy(service: str, digest: str) -> None:
    sh("docker", "rm", "-f", container(service), check=False)
    sh("docker", "run", "-d", "--name", container(service), "-p", f"127.0.0.1:{SERVICES[service]}:8080",
       "-e", f"SERVICE_NAME={service}", f"{repository(service)}@{digest}")


def running(service: str) -> str:
    """The registry digest of the image the service's container is running, as Docker reports it."""
    ref = sh("docker", "inspect", container(service), "--format", "{{.Config.Image}}")
    image_id = sh("docker", "inspect", container(service), "--format", "{{.Image}}")
    digests = json.loads(sh("docker", "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"))
    if "@" in ref and any(d == ref for d in digests):
        return ref.split("@", 1)[1]
    mine = [d for d in digests if d.startswith(repository(service) + "@")]
    if len(mine) != 1:
        raise SystemExit(f"cannot tell which registry digest {container(service)} runs")
    return mine[0].split("@", 1)[1]


def scan(ref: str) -> bytes:
    """A real Trivy scan of an image in the local registry. The database is never updated here."""
    return sh("docker", "run", "--rm", "--network", "host", "-v", f"{CACHE_VOLUME}:/root/.cache", TRIVY_IMAGE,
              "image", "--quiet", "--insecure", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln",
              "--format", "json", ref).encode()


def up() -> dict:
    registry_up()
    db = trivy_db()
    deployed = {}
    for service in SERVICES:
        digest = build(service, "vulnerable")
        deploy(service, digest)
        deployed[service] = digest
    return {"trivy_db": db, "deployed": deployed}


def down() -> None:
    for name in [container(s) for s in SERVICES] + ["axiom-demo-registry"]:
        sh("docker", "rm", "-f", name, check=False)


def main(argv: list[str]) -> None:
    cmd, *rest = argv or ["help"]
    if cmd == "up":
        print(json.dumps(up(), indent=2))
    elif cmd == "build":
        print(build(*rest))
    elif cmd == "deploy":
        deploy(*rest)
    elif cmd == "running":
        print(running(*rest))
    elif cmd == "scan":
        Path(rest[1]).write_bytes(scan(rest[0]))
    elif cmd == "down":
        down()
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
