# Checkpoint-7 baseline (checked 2026-10-22 ~15:50Z to 16:15Z)
- Tag checkpoint-6 (annotated, bc16c241) -> 1eed24c28e3240eaf92a5efa29ca443f06fad02a; working tree clean.
- Delivered checkpoint-6 files: sha256sum -c SHA256SUMS -> all 6 OK. Checkpoint-5 files: OK (not modified).
- History 622f216..1eed24c: 9 commits. After the checkpoint-6 CI commit (9c7303c): 30044e9 (test-only) and 1eed24c (docs).
- 30044e9 changes tests/integration/test_analyst_ui_workflows.py only (5+/4-): four exact equality assertions on the case
  header (`inner_text() == X`) became waits (`filter(has_text=X).wait_for()`). Effect: synchronisation fixed (the header
  refetches after a command). Weakening found: Playwright `has_text` with a string is a case-insensitive SUBSTRING match,
  so the check became less exact than equality. With the workflow values in use (closed, investigating,
  review_required) no other value contains these strings, so no false pass is possible today, and a missing value still
  times out and fails. Coverage and failure detection were otherwise unchanged. Tightened at checkpoint 7 to an exact
  anchored match.
- Clean-clone CI on the final checkpoint-6 revision 1eed24c28e3240eaf92a5efa29ca443f06fad02a (tree d9b683b3...,
  executable inputs sha256:6ff56a8b...): CI PASS, every stage; foundation 489 passed, 2 skipped (physical drill run as
  its own stage: passed; opt-in real-provider test never run); Compose smoke pass. This covers the test-only commit
  30044e9, which the checkpoint-6 CI (on 9c7303c) did not.
