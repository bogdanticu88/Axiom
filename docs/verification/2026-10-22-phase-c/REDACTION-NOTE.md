# Edit to foundation-verify.log (2026-10-22, checkpoint 5)

The checkpoint-5 CI run's secret scan flagged this archived log. It was committed with the checkpoint-4 records after
that checkpoint's CI run, so it had never been scanned. pytest had echoed the synthetic test values of
`test_redaction` (an AWS-key-shaped string and a private-key header, built at runtime in the test) into four test-ID
lines. Only those test IDs were replaced with `<fake ... removed>` markers; no other byte changed. The scanner was not
weakened, and the test now uses explicit IDs so the values no longer reach logs.

sha256 of the log as committed at checkpoint 4 (before this edit): `106b57a4986e1bbc56cd1e6fd01509e9f1a6bedb445426622236630eb17c9642`
