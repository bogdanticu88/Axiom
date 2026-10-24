# An expired lease is lost at every write (verification run 31)

`pytest -rA` summaries against the PostgreSQL test database (`scripts/dev/test-db.sh`).

| File | Code under test | Result |
|---|---|---|
| `before-fix.txt` | `main` at `5be8aee`: the final write did not test expiry | the 10 expired-outcome cases failed ("the expired worker's outcome was written"); the valid-lease control passed |
| `fix-removed.txt`, `fix-removed-reasons.txt` | this change with the previous authorization semantics put back (heartbeat without the expiry test; expiry tested inside the locking query, before any lock wait) | of the 20 lease tests that existed then, 6 failed, each for its intended reason; the 14 others cover cases the previous code already handled. The 21st (database boundary) was added afterwards and not run here |
| `after-fix.txt` | this change | all 21 lease tests passed, including the database-boundary test |

Heartbeat revival on the first head of this change (`0b86a5c`, where only the final write had been fixed), observed
with `test_running_heartbeat_does_not_revive_an_expired_lease_for_the_final_write`: the worker's heartbeat thread renewed
the expired lease, and the final write then recorded the job as `succeeded` with the late worker's result.
