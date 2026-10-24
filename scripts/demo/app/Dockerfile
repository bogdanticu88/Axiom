# syntax=mirror.gcr.io/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Demonstration service. REQUIREMENTS selects the vulnerable or the fixed dependency set; everything else is equal.
ARG PYTHON_IMAGE=mirror.gcr.io/library/python:3.13-slim@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f
FROM ${PYTHON_IMAGE}
ARG REQUIREMENTS=requirements-vulnerable.txt
WORKDIR /srv
COPY ${REQUIREMENTS} requirements.txt
RUN --mount=type=secret,id=ca,required=false sh -c '\
    if [ -f /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.txt'
COPY app.py .
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin demo
USER 10001
EXPOSE 8080
CMD ["python", "app.py"]
