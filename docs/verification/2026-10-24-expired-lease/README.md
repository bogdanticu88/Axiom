# Outcome returned after the lease expired (verification run 31)

Both files are `pytest -rA` summaries of the same selection, run against the PostgreSQL test database
(`scripts/dev/test-db.sh`):

    pytest tests/integration/test_jobs.py -k "after_the_lease_expired or still_valid"

* `before-fix.txt`: the new tests on `main` at `5be8aee` with `backend/axiom/jobs/worker.py` unchanged. Every expired
  case failed on its first assertion, "the expired worker's outcome was written"; the valid-lease control passed.
* `after-fix.txt`: the same tests with the fix: all passed.
