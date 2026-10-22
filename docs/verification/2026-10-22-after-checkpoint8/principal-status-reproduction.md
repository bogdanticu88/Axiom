# Disabled principals: reproduction before the fix

`tests/integration/test_principal_status.py` was written and run against `141d04a` (before `ee98742`).

| Test | Result before the fix | Why |
|---|---|---|
| a disabled verification identity cannot record a result | **failed**: job `succeeded` | the authority check ignored principal status; workload identities never authenticate |
| an action approved by a since-disabled approver is not executed | **failed**: execution `succeeded` | the execution recheck used the same check |
| a disabled principal holds no permission in the database | failed for a test defect (it named a permission the analyst does not hold); corrected to `investigation.request` but not rerun before the fix. Its failure without the fix is shown below by removing migration 0020 | `axiom.holds_permission` ignored principal status |
| a disabled principal bound directly is refused | **failed** (`DID NOT RAISE PermissionDenied`) | same cause |
| a suspended tenant refuses the next command and its workers stop | passed | row-level security checks tenant status on every statement |
| an expired membership refuses the next command | passed | membership validity was already checked |

A test for binding expiry was dropped as a duplicate of `cases::test_expired_binding_denied` (the first version also
tried to update a binding directly, which the binding guard rightly refuses).

After `ee98742`: all 7 tests in the file pass. Each half of the fix was removed in turn: without the application check,
three tests fail (the verification job is retried and stays queued because the database guard now refuses the
recording); without migration 0020, the database test fails.
