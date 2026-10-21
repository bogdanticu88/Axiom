# syntax=docker/dockerfile:1.7
# Backend image: API, migrations, provisioning and (later) workers share this image.
# Base image pinned by digest (python 3.13-slim, resolved 2026-10-22).
ARG PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.13-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f

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
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready',timeout=2).status==200 else 1)"
CMD ["python", "-m", "axiom.server"]
