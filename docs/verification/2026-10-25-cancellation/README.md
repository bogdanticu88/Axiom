# Cancellation settled from the effect evidence (verification run 33)

`pytest -rA` output against the PostgreSQL test database (`scripts/dev/test-db.sh`). Paths in tracebacks are shortened
to the repository root.

| File | Code under test | Result |
|---|---|---|
| `probe-on-prior-pr-head.txt` | `probe-abandon-and-cancel.py.txt` on the previous head of this change (`5e17eff`) | abandon after a witness park returned the use and allowed a second execution; cancel after an unknown outcome recorded `cancelled`; cancel of a parked execution raised the transition guard error |
| `on-prior-pr-head.txt` | `tests/integration/test_action_cancellation.py` on `5e17eff` | 19 failed, 4 passed |
| `on-main.txt` | the same tests on `main` (`8f8a3e6`), with this change's `test_actions.py` for the shared helpers | 19 failed, 4 passed |
| `after-change.txt` | this change | 23 passed at run 33; regenerated in run 34 with the added tests (30 passed) |
| `adopt-on-earlier-code.txt` | the two adoption tests with the refusal assertion replaced by a print, on `5e17eff` and `main` | what an unverifiable adoption did before |

`probe-abandon-and-cancel.py.txt` is a throwaway test used to establish the behaviour before changing it; it is not
part of the suite. The four tests that pass on the earlier code cover behaviour that was already right and is kept.

Run 34 (same folder):

| File | Code under test | Result |
|---|---|---|
| `witness-on-24e2dfd.txt` | the six witness-clearance tests on `24e2dfd` | 5 failed (4: use released without clearance; 1: the healthy API case, changed by design), 1 passed |
| `lock-order-control.txt` | the lock-order test on this change with the observation write's job-row lock removed | failed: `deadlock detected`, outcome record aborted, intent left `executing` |
| `after-change.txt` | this change, whole new file | regenerated after the run-34 changes |

Run 35:

| File | Code under test | Result |
|---|---|---|
| `rollback-drill-on-24e2dfd.txt` | `tests/drills/test_action_restore_boundary.py` on `24e2dfd` | failed: the API cancellation released the use after a physical rollback lost the intent; after acknowledgement the approval created a second ticket |
| `rollback-drill-final.txt` | both drills on the final head | 2 passed; use held, one ticket |

