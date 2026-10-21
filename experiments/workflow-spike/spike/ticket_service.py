"""Fake external ticket system, run as a separate process.

    python -m spike.ticket_service --port 8099 --db tickets.db [--no-lookup]

* POST /tickets            {"idempotency_key": k, "payload": {...}} -> 201 {"id": ...}
  Deliberately does NOT deduplicate on the key: a naive retry creates a duplicate ticket,
  which is what makes the lost-acknowledgement scenario meaningful.
* GET  /tickets?idempotency_key=k -> 200 {"tickets": [...]}, or 501 when started with --no-lookup
  (models an external system with no way to search by our key).
* GET  /admin/tickets       -> every ticket (test/operator out-of-band view, always available)
* GET  /health
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--no-lookup", action="store_true")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db, check_same_thread=False, isolation_level=None)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, idempotency_key TEXT, payload TEXT)"
    )
    lock = threading.Lock()

    def rows(where: str = "", params: tuple = ()) -> list[dict]:
        with lock:
            cur = conn.execute(f"SELECT id, idempotency_key, payload FROM tickets {where} ORDER BY rowid", params)
            return [{"id": r[0], "idempotency_key": r[1], "payload": json.loads(r[2])} for r in cur]

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            if url.path == "/health":
                return self._send(200, {"ok": True, "lookup": not args.no_lookup})
            if url.path == "/admin/tickets":
                return self._send(200, {"tickets": rows()})
            if url.path == "/tickets":
                if args.no_lookup:
                    return self._send(501, {"error": "lookup by idempotency key not supported"})
                key = parse_qs(url.query).get("idempotency_key", [""])[0]
                return self._send(200, {"tickets": rows("WHERE idempotency_key=?", (key,))})
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/tickets":
                return self._send(404, {"error": "not found"})
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            tid = "TCK-" + uuid.uuid4().hex[:8]
            with lock:
                conn.execute(
                    "INSERT INTO tickets VALUES (?,?,?)",
                    (tid, body["idempotency_key"], json.dumps(body["payload"], sort_keys=True)),
                )
            self._send(201, {"id": tid})

        def log_message(self, fmt: str, *a) -> None:
            print("ticket-service:", fmt % a, flush=True)

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"TICKET SERVICE READY port={args.port} lookup={not args.no_lookup}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
