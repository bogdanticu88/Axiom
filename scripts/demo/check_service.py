"""Check service for the remediation demonstration, implementing the axiom-check/2 contract (ADR 0014).

What it checks, exactly: for the asset named in the request it asks Docker which image the demo container for that
asset is running right now, then runs a real Trivy scan of that image (by registry digest, with the cached database
and no database update). A condition {vulnerability_ref, component} is reported "present" when the scan lists the
same vulnerability ID on a package with the same identity, ignoring the version (pkg:pypi/jinja2@3.1.2 matches
pkg:pypi/jinja2@3.1.6). It is "absent" when the scan completed and does not list it, and "error" when the scan
failed. The examined digest and the observation time are reported so Axiom can bind the result to the deployment
that was reported as changed.

What it does not check: whether the vulnerable code is reachable, other replicas or hosts, anything loaded at run
time outside the image, or whether the Trivy database is complete for this package. Its answer is a claim. Axiom
stores it as evidence but cannot prove it; see docs/DEMO.md for what a compromised service could assert.

Usage (started by the demonstration; it needs the Docker CLI and the lab from lab.py):
    python scripts/demo/check_service.py --cert server.pem --key server.key --token-file token --port 18443
"""
from __future__ import annotations

import argparse
import hmac
import json
import ssl
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402

SCHEMA = "axiom-check/2"


def package_identity(purl: str) -> str:
    """pkg:pypi/jinja2@3.1.2 -> pkg:pypi/jinja2 (qualifiers and version dropped, name compared case-insensitively)."""
    return purl.split("?", 1)[0].split("@", 1)[0].lower()


def findings(report: dict) -> set[tuple[str, str]]:
    seen = set()
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL") or f"{v.get('PkgName')}@{v.get('InstalledVersion')}"
            seen.add((v.get("VulnerabilityID"), package_identity(purl)))
    return seen


def examine(request: dict) -> dict:
    name = (request.get("asset") or {}).get("name", "")
    service = next((s for s in lab.SERVICES if lab.repository(s) == name), None)
    answer = {"schema": SCHEMA, "request_id": request.get("request_id"), "nonce": request.get("nonce"),
              "asset_id": (request.get("asset") or {}).get("id")}
    if service is None:
        return {**answer, "coverage": "partial", "results": [], "detail": f"no demo service for asset {name!r}"}
    observed_at = datetime.now(timezone.utc)
    digest = lab.running(service)
    ref = f"{lab.repository(service)}@{digest}"
    try:
        report = json.loads(lab.scan(ref))
        seen, scan_error = findings(report), None
    except (SystemExit, ValueError) as exc:
        seen, scan_error = set(), str(exc)[:300]
    results = []
    for criterion in request.get("criteria") or []:
        checked = []
        for cond in criterion.get("conditions") or []:
            key = (cond.get("vulnerability_ref"), package_identity(cond.get("component") or ""))
            checked.append({**cond, "found": None if scan_error else key in seen})
        if scan_error:
            outcome = "error"
        else:
            outcome = "present" if any(c["found"] for c in checked) else "absent"
        results.append({"criterion": criterion.get("id"), "result": outcome, "conditions": checked})
    return {**answer, "deployment_digest": digest, "observed_at": observed_at.isoformat(),
            "coverage": "partial" if scan_error else "complete", "results": results,
            "examined": {"container": lab.container(service), "image": ref, "scanner": "trivy",
                         "scanner_image": lab.TRIVY_IMAGE,
                         "database_updated_at": None if scan_error else _db_updated()},
            **({"scan_error": scan_error} if scan_error else {})}


def _db_updated() -> str | None:
    try:
        return json.loads(lab.sh("docker", "run", "--rm", "-v", f"{lab.CACHE_VOLUME}:/c", "--entrypoint", "cat",
                                 lab.TRIVY_IMAGE, "/c/trivy/db/metadata.json")).get("UpdatedAt")
    except (SystemExit, ValueError):
        return None


def serve(port: int, cert: str, key: str, token: str) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            supplied = self.headers.get("Authorization", "")
            if self.path != "/v1/checks" or not hmac.compare_digest(supplied, f"Bearer {token}"):
                self.send_response(401 if self.path == "/v1/checks" else 404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length") or 0)
            try:
                request = json.loads(self.rfile.read(length))
                body = json.dumps(examine(request)).encode()
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            sys.stderr.write("check-service: " + fmt % args + "\n")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"check-service: listening on https://localhost:{port}/v1/checks", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=18443)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--token-file", required=True)
    a = p.parse_args()
    serve(a.port, a.cert, a.key, Path(a.token_file).read_text().strip())
