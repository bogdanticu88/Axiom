"""External restore witness (ADR 0010).

The database fingerprint (ADR 0006) detects a restore into a different cluster, timeline or database. It cannot
detect a rollback that keeps all three, for example a storage snapshot of the same data directory or a logical
restore into a database recreated with the same OID, and any marker kept *inside* the database is rolled back
with it. The witness keeps the highest effect watermark outside the database:

* the gate draws a watermark from ``axiom.effect_watermark_seq`` in the transaction that marks an intent executing
  and records it here **before** the request is sent;
* a database whose watermark is lower than the witness has lost effects it once recorded, so workers refuse to
  run and effects park until an operator reconciles and acknowledges (which moves the sequence past the witness).

Each worker writes only its own record and only upwards, so concurrent workers never lower the high-water mark.
The witness only helps if it is **not** restored together with the database: keep it in a different backup domain
(another bucket or account without point-in-time rollback tied to the database backups). If both are rolled back
together the rollback is invisible; that blind spot is tested and documented.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import psycopg

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


class FileWitness:
    """Directory of per-worker files. For single-host installs and tests; use a separate volume from the database."""

    def __init__(self, directory: Path | str, worker_id: str):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.name = _SAFE.sub("_", worker_id)
        self._lock = threading.Lock()
        self._last = self._read(self.dir / self.name) or 0

    @staticmethod
    def _read(path: Path) -> int | None:
        try:
            return int(path.read_text().strip())
        except (FileNotFoundError, ValueError):
            return None

    def advance(self, watermark: int) -> None:
        with self._lock:
            if watermark <= self._last:
                return
            tmp = self.dir / f".{self.name}.tmp"
            with open(tmp, "w") as fh:
                fh.write(str(watermark))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.dir / self.name)
            dir_fd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            self._last = watermark

    def high_water(self) -> int | None:
        values = [v for p in self.dir.iterdir() if not p.name.startswith(".")
                  if (v := self._read(p)) is not None]
        return max(values) if values else None


class S3Witness:
    """Per-worker objects under a prefix in an S3-compatible bucket (keep it outside the database backup domain)."""

    def __init__(self, client, bucket: str, prefix: str, worker_id: str):
        self.client, self.bucket = client, bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.key = self.prefix + _SAFE.sub("_", worker_id)
        self._lock = threading.Lock()
        self._last = 0

    def advance(self, watermark: int) -> None:
        with self._lock:
            if watermark <= self._last:
                return
            self.client.put_object(Bucket=self.bucket, Key=self.key, Body=str(watermark).encode())
            self._last = watermark

    def high_water(self) -> int | None:
        best = None
        for page in self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                body = self.client.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read()
                try:
                    value = int(body.decode().strip())
                except ValueError:
                    continue
                best = value if best is None else max(best, value)
        return best


def database_watermark(conn: psycopg.Connection) -> int:
    row = conn.execute("SELECT last_value, is_called FROM axiom.effect_watermark_seq").fetchone()
    return int(row["last_value"]) if row["is_called"] else 0


def check(conn: psycopg.Connection, witness) -> str | None:
    """Return why effects must not run, or None. Compares the database watermark with the external witness."""
    if witness is None:
        return None
    db_value = database_watermark(conn)
    external = witness.high_water()
    if external is None:
        return (f"restore witness is empty but the database has issued effect watermark {db_value}; the witness "
                "was lost or replaced") if db_value > 0 else None
    if external > db_value:
        return (f"database effect watermark {db_value} is behind the external witness {external}: the database "
                "was restored or rolled back after effects were recorded")
    return None
