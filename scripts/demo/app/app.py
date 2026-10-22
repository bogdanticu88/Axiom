"""A deliberately small web service for the remediation demonstration.

It renders one page with Jinja2. The vulnerable build pins Jinja2 3.1.2, which has published advisories; the fixed
build pins 3.1.6. The service itself does not exercise the vulnerable code paths: the demonstration is about finding,
deciding on, changing and verifying a dependency, not about exploiting it.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jinja2

PAGE = jinja2.Environment(autoescape=True).from_string(
    "<!doctype html><title>{{ name }}</title><p>{{ name }} is running with Jinja2 {{ version }}.</p>")
NAME = __import__("os").environ.get("SERVICE_NAME", "demo service")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = PAGE.render(name=NAME, version=jinja2.__version__).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
