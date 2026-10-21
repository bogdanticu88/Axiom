# ADR 0005: Evidence storage and finalisation

Status: accepted (2026-10-22)

## Decision
* **Metadata in PostgreSQL, bytes in S3-compatible storage** behind an `ObjectStore` interface (filesystem
  implementation for development and tests, refused in production; S3 implementation for anything else).
* **Uploads stream through the API.** No client-writable pre-signed PUT URLs are issued, so a leaked upload capability
  cannot replace bytes after finalisation. The declared size is a hard limit during streaming.
* **Finalisation re-reads storage**, recomputes SHA-256 and size, and marks the record `verified` or `rejected`
  (`digest_mismatch`, `size_mismatch`). Status transitions are enforced by a trigger; verified digests are immutable.
* **Only verified evidence** may support decisions (service check and `decision_evidence` trigger) or a passed
  verification.
* **Reads** require the classification-specific permission (`evidence.read:internal|confidential|restricted`), are
  audited and committed before any byte is returned, and re-hash while streaming; a mismatch aborts the stream and
  records `evidence.integrity_mismatch`.
* **Compose uses SeaweedFS 4.48** (digest-pinned). MinIO community images could not be pulled from this environment
  (Docker Hub denied, quay.io unauthorised); SeaweedFS and Garage were available. Production targets any S3-compatible
  service, typically the cloud provider's object store.

## Limits
A matching hash shows stored bytes equal what the uploader declared, not that the content is true. Detection on read
is not prevention: object-lock/immutable retention and independently stored signed checkpoints (EVD-08) are planned.
Retention, deletion jobs and legal holds (EVD-06, EVD-07, A20) are not built.

## Verification
tests/integration/test_evidence_outbox.py (filesystem) and tests/integration/test_s3_store.py (SeaweedFS), plus the
Compose smoke test (upload, verify, download, rejected mismatch).
