"""Run the API with uvicorn using environment configuration (AXIOM_*)."""
from __future__ import annotations

import logging
import os
import re

import uvicorn

from .api.app import create_app
from .config import Settings

# The sign-in callback carries a single-use authorization code and the state in its query string. The access log
# records request lines, so their query strings are removed before they reach any handler.
_SENSITIVE_PATHS = re.compile(r"^(/auth/callback|/auth/login)(\?.*)?$")


class RedactSignInQuery(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            m = _SENSITIVE_PATHS.match(args[2])
            if m and m.group(2):
                record.args = (*args[:2], m.group(1) + "?[redacted]", *args[3:])
        return True


def build(app) -> uvicorn.Server:
    """The server as deployed: forwarding headers ignored (TLS ends at the operator's proxy; see
    docs/DEPLOYMENT-TRUST-BOUNDARY.md) and sign-in query strings redacted from the access log."""
    config = uvicorn.Config(app, host=os.environ.get("AXIOM_BIND_HOST", "0.0.0.0"),
                            port=int(os.environ.get("AXIOM_PORT", "8000")), proxy_headers=False, server_header=False)
    access = logging.getLogger("uvicorn.access")       # after uvicorn configured its loggers
    if not any(isinstance(f, RedactSignInQuery) for f in access.filters):
        access.addFilter(RedactSignInQuery())
    return uvicorn.Server(config)


def main() -> None:
    logging.basicConfig(level=os.environ.get("AXIOM_LOG_LEVEL", "INFO"))
    build(create_app(Settings())).run()


if __name__ == "__main__":
    main()
