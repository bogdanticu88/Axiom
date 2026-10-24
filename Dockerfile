# syntax=mirror.gcr.io/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Backend image: API (with the built analyst UI), migrations, provisioning and workers share this image.
# Base images pinned by digest (python 3.13-slim resolved 2026-10-22; node 22.20.0-slim published 2025-09-24).
ARG PYTHON_IMAGE=mirror.gcr.io/library/python:3.13-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f
ARG NODE_IMAGE=mirror.gcr.io/library/node:22.20.0-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e

# Analyst UI: locked install (package-lock.json), type check and production build. Only the static output is kept.
FROM ${NODE_IMAGE} AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=secret,id=ca,required=false sh -c '\
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \
    npm ci --no-audit --no-fund --ignore-scripts'
COPY frontend/ ./
RUN npm run build

FROM ${PYTHON_IMAGE} AS build
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY backend ./backend
# Optional build secret 'ca' supplies an extra CA bundle for builds behind a TLS-intercepting proxy.
RUN --mount=type=secret,id=ca,required=false sh -c '\
    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca PIP_CERT=/run/secrets/ca UV_NATIVE_TLS=1; fi; \
    pip install --no-cache-dir uv==0.11.32 && \
    uv sync --frozen --no-dev --no-editable'

FROM ${PYTHON_IMAGE}
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin axiom
WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
COPY --chown=root:root db /app/db
COPY --from=ui --chown=root:root /ui/dist /app/ui
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Restore witness mount point (ADR 0010); a named volume mounted here inherits this ownership.
RUN mkdir -p /var/lib/axiom/witness && chown 10001:10001 /var/lib/axiom/witness
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready',timeout=2).status==200 else 1)"
CMD ["python", "-m", "axiom.server"]
