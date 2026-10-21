"""Fake external ticket system, run as a separate process.

Same design as experiments/workflow-spike/spike/ticket_service.py (so results are comparable),
plus switches for defence-in-depth and failure injection:

    python -m pgspike.ticket_service --port 8099 --db tickets.db
        [--no-lookup] [--dedupe] [--fencing] [--fail-first N] [--fail-after-create N] [--delay-ms MS]

* POST /tickets {"idempotency_key": k, "fencing_token": t, "payload": {...}, "meta": {...}}
  -> 201 {"id": ...}
  By default it does NOT deduplicate on the key (a naive retry creates a duplicate) and ignores the
  fencing token, exactly like the Temporal spike's service.
  --dedupe      external idempotency: a repeated key returns 200 with the existing ticket id.
  --fencing     remembers the highest fencing token seen per key and rejects a lower one with 409.
  --fail-first N         the first N POSTs return 503 {"created": false} (definite, transient).
  --fail-after-create N  the first N successful creates still answer 500 (ambiguous: effect happened).
  --delay-ms MS          sleep before handling each POST (to make concurrency observable).
* GET /tickets?idempotency_key=k -> 200 {"tickets": [...]}, or 501 with --no-lookup.
* GET /admin/tickets -> every ticket (out-of-band view for tests/operators). GET /health.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--no-lookup", action="store_true")
    ap.add_argument("--dedupe", action="store_true")
    ap.add_argument("--fencing", action="store_true")
    ap.add_argument("--fail-first", type=int, default=0)
    ap.add_argument("--fail-after-create", type=int, default=0)
    ap.add_argument("--delay-ms", type=int, default=0)
    args = ap.parse_args()

    conn = sqlite3.connect(args.db, check_same_thread=False, isolation_level=None)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, idempotency_key TEXT, fencing_token INTEGER,"
        " payload TEXT, meta TEXT, created_at REAL)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS key_tokens (key TEXT PRIMARY KEY, max_token INTEGER)")
    lock = threading.Lock()
    counters = {"posts": 0, "creates": 0}

    def rows(where: str = "", params: tuple = ()) -> list[dict]:
        with lock:
            cur = conn.execute(
                f"SELECT id, idempotency_key, fencing_token, payload, meta, created_at FROM tickets {where} ORDER BY rowid",
                params,
            )
            return [
                {"id": r[0], "idempotency_key": r[1], "fencing_token": r[2], "payload": json.loads(r[3]),
                 "meta": json.loads(r[4]) if r[4] else None, "created_at": r[5]}
                for r in cur
            ]

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
            if args.delay_ms:
                time.sleep(args.delay_ms / 1000)
            key, token = body["idempotency_key"], body.get("fencing_token")
            with lock:
                counters["posts"] += 1
                if counters["posts"] <= args.fail_first:
                    code, resp = 503, {"error": "transient failure (injected)", "created": False}
                else:
                    code, resp = None, None
                    if args.fencing and token is not None:
                        row = conn.execute("SELECT max_token FROM key_tokens WHERE key=?", (key,)).fetchone()
                        if row and token < row[0]:
                            code, resp = 409, {"error": f"stale fencing token {token} < {row[0]}", "created": False}
                        else:
                            conn.execute("INSERT OR REPLACE INTO key_tokens VALUES (?,?)",
                                         (key, max(token, row[0] if row else token)))
                    if code is None and args.dedupe:
                        row = conn.execute("SELECT id FROM tickets WHERE idempotency_key=? ORDER BY rowid LIMIT 1",
                                           (key,)).fetchone()
                        if row:
                            code, resp = 200, {"id": row[0], "deduplicated": True}
                    if code is None:
                        tid = "TCK-" + uuid.uuid4().hex[:8]
                        conn.execute(
                            "INSERT INTO tickets VALUES (?,?,?,?,?,?)",
                            (tid, key, token, json.dumps(body["payload"], sort_keys=True),
                             json.dumps(body.get("meta")) if body.get("meta") else None, time.time()),
                        )
                        counters["creates"] += 1
                        if counters["creates"] <= args.fail_after_create:
                            code, resp = 500, {"error": "internal error after commit (injected)"}
                        else:
                            code, resp = 201, {"id": tid}
            self._send(code, resp)

        def log_message(self, fmt: str, *a) -> None:
            print("ticket-service:", fmt % a, flush=True)

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"TICKET SERVICE READY port={args.port} lookup={not args.no_lookup} dedupe={args.dedupe} "
          f"fencing={args.fencing} fail_first={args.fail_first} fail_after_create={args.fail_after_create}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
