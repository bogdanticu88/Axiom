"""A controlled local check endpoint for the verification worker tests (fixture, not a real integration).

Serves ``POST /v1/checks`` over TLS on 127.0.0.1 with a throwaway CA generated per test session. Each test sets
``target.behaviour`` to a function from the parsed request to ``(status, body)`` (body: dict, bytes or None) and
can inspect ``target.requests``. Nothing here talks to anything outside the test process.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _pki(directory: Path, hostnames: tuple[str, ...] = ()) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axiom test check CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                                                       + [x509.DNSName(h) for h in hostnames]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = directory / "ca.pem", directory / "server.pem", directory / "server.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return ca_path, cert_path, key_path


@dataclass
class CheckTarget:
    base_url: str
    ca_path: Path
    requests: list = field(default_factory=list)
    behaviour: object = None
    server: ThreadingHTTPServer | None = None

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def start(directory: Path, hostnames: tuple[str, ...] = ()) -> CheckTarget:
    """``hostnames`` are added to the certificate (besides 127.0.0.1) for tests that pin a name to this address."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_path, cert_path, key_path = _pki(directory, hostnames)
    target = CheckTarget("", ca_path)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            request = json.loads(body)
            target.requests.append({"path": self.path, "headers": dict(self.headers), "json": request})
            answer = target.behaviour(request) if target.behaviour else (500, None)
            status, payload = answer[0], answer[1]
            extra = answer[2] if len(answer) > 2 else {}
            data = payload if isinstance(payload, bytes) else (b"" if payload is None else json.dumps(payload).encode())
            self.send_response(status)
            if status in (301, 302, 307, 308) and "Location" not in extra:
                self.send_header("Location", "https://example.invalid/elsewhere")
            for k, v in extra.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target.server = server
    target.base_url = f"https://127.0.0.1:{server.server_address[1]}"
    return target
