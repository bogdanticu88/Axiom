# Action execution transitions after the effect (verification run 32)

`pytest -rA` summaries against the PostgreSQL test database (`scripts/dev/test-db.sh`).

| File | Code under test | Result |
|---|---|---|
| `on-main.txt` | the new tests with `domains/actions/jobs.py` and `service.py` from `main` (`8f8a3e6`) | 8 of 8 failed, each for its intended reason |
| `fence-without-reconcile-fix.txt` | the fenced handler with `main`'s `reconcile` | adopting a discarded stale success left the execution `reconciling`; a contradicting reference was not refused |
| `after-fix.txt` | this change | 8 of 8 passed |

The two `probe-*.py.txt` files are throwaway tests used during the investigation, kept for reproducibility; they are
not part of the suite. `probe-cancel-after-worker-loss` printed `job: cancelled | execution: prepared | reservation:
reserved | tickets: 0` on `main`'s code, before the fix was applied; this change does not touch that path (a known gap,
not fixed here). `probe-reconcile-after-stale-success` printed, with
the fence but before the reconcile fix, `adopt : succeeded reconciling None reserved` and `not_applied : succeeded
succeeded SEC-1 consumed`, with one create request in both.
