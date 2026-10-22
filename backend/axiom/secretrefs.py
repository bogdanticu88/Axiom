"""Secret references: the one place configuration secrets are read (ADR 0013 amendment 2).

Configuration never holds a secret value, only a reference:

* ``secretref:file/<absolute path>``: a file the deployment mounts (Docker or Compose secrets, Kubernetes Secret
  volumes, systemd credentials). Allowed in every environment. The path must be absolute, resolve (after symlinks,
  which Kubernetes uses) inside one of the allowed directories (``AXIOM_SECRET_FILE_DIRS``, default ``/run/secrets``),
  name a regular file of at most 4096 bytes, and hold a non-empty value; one trailing newline is removed.
* ``secretref:env/<NAME>``: an environment variable. **Development and test only**; refused when the environment is
  production, because environment variables leak into process listings, crash dumps and child processes.

Errors never contain the secret value. No cloud secret service is required; a deployment that uses one can mount its
secrets as files (for example through a CSI driver), which this resolver then reads.
"""
from __future__ import annotations

import os
from pathlib import Path

from .errors import ConfigurationError

MAX_SECRET_BYTES = 4096
DEFAULT_FILE_DIRS = ("/run/secrets",)


class SecretRefResolver:
    def __init__(self, *, env: str, file_dirs: tuple[str, ...] = DEFAULT_FILE_DIRS):
        self.env = env
        self.file_dirs = tuple(Path(d).resolve() for d in file_dirs if d)

    @classmethod
    def from_environment(cls) -> "SecretRefResolver":
        dirs = os.environ.get("AXIOM_SECRET_FILE_DIRS")
        return cls(env=os.environ.get("AXIOM_ENV", "development"),
                   file_dirs=tuple(d.strip() for d in dirs.split(",")) if dirs else DEFAULT_FILE_DIRS)

    def resolve(self, ref: str) -> str:
        if not isinstance(ref, str) or not ref.startswith("secretref:"):
            raise ConfigurationError("a secret must be given as a secretref:file/... or secretref:env/... reference")
        if ref.startswith("secretref:file/"):
            return self._file(ref.removeprefix("secretref:file"))
        if ref.startswith("secretref:env/"):
            if self.env == "production":
                raise ConfigurationError("environment secret references are not permitted in production; "
                                         "mount the secret as a file and use secretref:file/<path>")
            value = os.environ.get(ref.removeprefix("secretref:env/"))
            if not value:
                raise ConfigurationError("secret reference did not resolve")
            return value
        raise ConfigurationError("unsupported secret reference")

    def _file(self, raw: str) -> str:
        path = Path(raw)
        if not path.is_absolute():
            raise ConfigurationError("secret file reference must be an absolute path")
        try:
            real = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ConfigurationError("secret reference did not resolve") from None
        if not any(real == d or d in real.parents for d in self.file_dirs):
            raise ConfigurationError("secret file is outside the allowed secret directories")
        if not real.is_file():
            raise ConfigurationError("secret reference does not name a regular file")
        if real.stat().st_size > MAX_SECRET_BYTES:
            raise ConfigurationError("secret file is too large")
        try:
            value = real.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise ConfigurationError("secret file could not be read") from None
        value = value[:-1] if value.endswith("\n") else value
        if value.endswith("\r"):
            value = value[:-1]
        if not value.strip():
            raise ConfigurationError("secret file is empty")
        return value
