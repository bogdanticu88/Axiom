"""Prometheus text metrics for the job worker (opt-in HTTP endpoint).

Gauges are computed per tenant inside that tenant's RLS-bound transaction (the worker never uses a cross-tenant
role). Labels carry tenant IDs and job kinds only, never payloads. Counters are per worker process since start.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import collect


def render(worker) -> str:
    lines = ["# HELP axiom_jobs Jobs by tenant, kind and state", "# TYPE axiom_jobs gauge"]
    oldest, last_hour = [], []
    for ctx in worker.tenants():
        with worker.db.tenant_tx(ctx) as conn:
            m = collect(conn)
        t = str(ctx.tenant_id)
        for r in m["jobs_by_kind_state"]:
            lines.append(f'axiom_jobs{{tenant="{t}",kind="{r["kind"]}",state="{r["state"]}"}} {r["n"]}')
        oldest.append(f'axiom_jobs_oldest_due_seconds{{tenant="{t}"}} {m["oldest_due_seconds"]:.3f}')
        for name, n in sorted(m["last_hour"].items()):
            last_hour.append(f'axiom_job_events_last_hour{{tenant="{t}",event="{name}"}} {n}')
    lines += ["# HELP axiom_jobs_oldest_due_seconds Age of the oldest due, unclaimed job",
              "# TYPE axiom_jobs_oldest_due_seconds gauge", *oldest,
              "# HELP axiom_job_events_last_hour Job events in the last hour (lease expiries, fenced refusals, ...)",
              "# TYPE axiom_job_events_last_hour gauge", *last_hour,
              "# HELP axiom_worker_total Worker process counters since start", "# TYPE axiom_worker_total counter"]
    for name, n in sorted(worker.counters.items()):
        lines.append(f'axiom_worker_total{{worker="{worker.worker_id}",counter="{name}"}} {n}')
    return "\n".join(lines) + "\n"


def serve(worker, port: int, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            try:
                body = render(worker).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
            except Exception:  # noqa: BLE001 - never crash the worker for metrics
                body = b"# metrics collection failed\n"
                self.send_response(503)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence default stderr logging
            return

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True, name="metrics").start()
    return server
