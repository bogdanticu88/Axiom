"""Run the API with uvicorn using environment configuration (AXIOM_*)."""
from __future__ import annotations

import logging
import os

import uvicorn

from .api.app import create_app
from .config import Settings


def main() -> None:
    logging.basicConfig(level=os.environ.get("AXIOM_LOG_LEVEL", "INFO"))
    app = create_app(Settings())
    uvicorn.run(app, host=os.environ.get("AXIOM_BIND_HOST", "0.0.0.0"), port=int(os.environ.get("AXIOM_PORT", "8000")),
                proxy_headers=False, server_header=False)


if __name__ == "__main__":
    main()
