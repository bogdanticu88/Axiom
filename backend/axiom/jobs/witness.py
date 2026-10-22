"""External restore witness (ADR 0010).

The database fingerprint (ADR 0006) detects a restore into a different cluster, timeline or database. It cannot
detect a rollback that keeps all three, for example a storage snapshot of the same data directory or a logical
restore into a database recreated with the same OID, and any marker kept *inside* the database is rolled back
with it. The witness keeps the highest effect watermark outside the database:

* the gate draws a watermark from ``axiom.effect_watermark_seq`` in the transaction that marks an intent executing
  and records it here **before** the request is sent (a failed write rolls back and nothing is sent);
* a database whose watermark is lower than the witness has lost effects it once recorded, so workers refuse to
  run and effects park until an operator reconciles and acknowledges.

Records are **write-once**: one object or file per watermark, named ``<watermark:020d>-<worker>``. The high-water
mark is the largest name in a listing, so concurrent writers, duplicate worker IDs, retried writes after a lost
acknowledgement and partial failures can never lower it, and no read-modify-write or conditional write is needed.
Older records are pruned best-effort; see "Pruning" below and ADR 0010 for the invariant.

Pruning
-------
* **Who deletes**: a worker deletes only records whose parsed owner (``name[21:]``) *equals* its own sanitised ID,
  never another worker's (an exact comparison, so ``w1`` cannot prune ``a-w1``).
* **What**: only records named in the listing it has just read, and only those ranked below the newest ``KEEP`` of
  its own records in that listing.
* **Invariant**: every deleted record had at least ``KEEP`` (>= 1) records with a *higher* watermark present in the
  listing it came from. The record holding the global maximum has no higher record, so no worker, listing (stale,
  partial or paginated) or interleaving can delete it; the mark therefore never decreases. An interrupted prune only
  leaves extra records. Workers that share an ID (a misconfiguration) may prune each other's records, which still
  keeps the newest ``KEEP`` of that ID and never the maximum.
* Sanitisation maps characters outside ``[A-Za-z0-9._-]`` to ``_``, so distinct raw IDs can collide; the effect is
  the shared-ID case above.

The witness only helps if it is **not** restored together with the database: keep it in a different backup domain.
Its guarantees also depend on the storage: durable writes, and a listing that shows a completed write
(read-after-write list consistency). Those properties must be validated for each production store; the tests here
use SeaweedFS and a local directory only.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import psycopg

_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_NAME = re.compile(r"^(\d{20})-")
KEEP = 3


class WitnessUnavailable(RuntimeError):
    """The witness could not be read or written; effects must not proceed."""


def _record_name(watermark: int, worker: str) -> str:
    return f"{watermark:020d}-{worker}"


def _parse(name: str) -> int | None:
    m = _NAME.match(name)
    return int(m.group(1)) if m else None


def _owner(name: str) -> str | None:
    return name[21:] if _NAME.match(name) else None


def prune_candidates(names: list[str], worker: str, keep: int = KEEP) -> list[str]:
    """Record names this worker may delete from a listing (see "Pruning")."""
    mine = sorted((n for n in names if _owner(n) == worker), key=_parse)
    return mine[:-keep] if keep >= 1 else []


class FileWitness:
    """Directory of write-once records. For single-host installs and tests; use a separate volume from the database."""

    def __init__(self, directory: Path | str, worker_id: str):
        if not str(directory).strip():
            raise ValueError("witness directory is empty")
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.worker = _SAFE.sub("_", worker_id)
        self._lock = threading.Lock()

    def probe(self) -> None:
        """Fail at start-up if the directory cannot be listed or written."""
        tmp = self.dir / f".probe-{self.worker}"
        try:
            tmp.write_text("probe")
            tmp.unlink()
            list(self.dir.iterdir())
        except OSError as exc:
            raise WitnessUnavailable(f"witness directory {self.dir} is not usable: {exc}") from exc

    def advance(self, watermark: int) -> None:
        with self._lock:
            final = self.dir / _record_name(watermark, self.worker)
            if final.exists():
                return
            tmp = self.dir / f".{final.name}.tmp"
            with open(tmp, "w") as fh:
                fh.write(str(watermark))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)
            dir_fd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            self._prune()

    def _list(self) -> list[str]:
        return [p.name for p in self.dir.iterdir()]

    def _delete(self, name: str) -> None:
        (self.dir / name).unlink()

    def _prune(self) -> None:
        try:
            for name in prune_candidates(self._list(), self.worker):
                self._delete(name)
        except OSError:
            pass          # best effort: an interrupted prune only leaves extra records

    def high_water(self) -> int | None:
        try:
            values = [v for n in self._list() if (v := _parse(n)) is not None]
        except OSError as exc:
            raise WitnessUnavailable(f"witness directory unreadable: {exc}") from exc
        return max(values) if values else None


class S3Witness:
    """Write-once objects under a prefix in an S3-compatible bucket outside the database backup domain."""

    def __init__(self, client, bucket: str, prefix: str, worker_id: str, *, page_size: int | None = None):
        self.client, self.bucket, self.page_size = client, bucket, page_size
        self.prefix = prefix.strip("/") + "/"
        self.worker = _SAFE.sub("_", worker_id)
        self._lock = threading.Lock()

    def probe(self) -> None:
        """Fail at start-up unless the identity can write, list and delete under the prefix."""
        key = f"{self.prefix}_probe/{self.worker}"
        try:
            self.client.put_object(Bucket=self.bucket, Key=key, Body=b"probe")
            self.client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix, MaxKeys=1)
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except Exception as exc:  # noqa: BLE001 - any storage or permission error disables effects
            raise WitnessUnavailable(f"S3 witness s3://{self.bucket}/{self.prefix} is not usable: {exc}") from exc

    def advance(self, watermark: int) -> None:
        with self._lock:
            key = self.prefix + _record_name(watermark, self.worker)
            try:
                self.client.put_object(Bucket=self.bucket, Key=key, Body=str(watermark).encode())
            except Exception as exc:  # noqa: BLE001
                raise WitnessUnavailable(f"could not record watermark {watermark}: {exc}") from exc
            self._prune()

    def _list(self) -> list[str]:
        """Names (without the prefix) of every object under the prefix, following all pages. Keys in a deeper
        "directory" (e.g. the probe) never parse as records."""
        names = []
        cfg = {"PageSize": self.page_size} if self.page_size else {}
        for page in self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix,
                                                                          PaginationConfig=cfg):
            names += [o["Key"][len(self.prefix):] for o in page.get("Contents", [])]
        return names

    def _delete(self, name: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self.prefix + name)

    def _prune(self) -> None:
        try:
            for name in prune_candidates(self._list(), self.worker):
                self._delete(name)
        except Exception:  # noqa: BLE001 - pruning is best effort and can never lower the mark
            pass

    def high_water(self) -> int | None:
        try:
            values = [v for n in self._list() if (v := _parse(n)) is not None]
        except Exception as exc:  # noqa: BLE001
            raise WitnessUnavailable(f"S3 witness unreadable: {exc}") from exc
        return max(values) if values else None


def database_watermark(conn: psycopg.Connection) -> int:
    row = conn.execute("SELECT last_value, is_called FROM axiom.effect_watermark_seq").fetchone()
    return int(row["last_value"]) if row["is_called"] else 0


def check(conn: psycopg.Connection, witness) -> str | None:
    """Return why effects must not run (restore or rollback detected), or None. Compares the database watermark
    with the external witness. An unreadable witness raises ``WitnessUnavailable`` (fail closed, but transient:
    callers retry later rather than asking an operator)."""
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
