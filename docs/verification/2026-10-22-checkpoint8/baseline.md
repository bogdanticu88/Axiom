# Checkpoint-8 baseline (checked 2026-10-22, before any checkpoint-8 change)

Private development history (the repository before publication):
- Tag checkpoint-7 -> 4c24c5d3076e7bdec5d0144c774c6f3aefc5ce28. The delivered checkpoint-7 files match SHA256SUMS
  (6 of 6); checkpoint-6 (6) and checkpoint-5 (5) files still match theirs.
- The bundle clones and its checkpoint-7 tag resolves to the same commit; the source archive is identical to the tag's
  tree; the screenshot and review-package archives contain the files the manifest lists.
- Commits after the clean-clone CI commit (b6170c6) up to the tag change only docs/VERIFICATION.md and
  docs/verification/2026-10-22-checkpoint7/ci-b6170c6.log: records and logs, no code or tests.

Published Axiom history (rewritten for publication: renamed, authorship and messages rewritten):
- checkpoint-7 -> 421aa60958d32582aa0a9060c56e3a45dd91fdb3; the rewritten CI commit is f65e5dd; between them the same
  two record files change.
- After the tag: "Tidy comments and docstrings" (backend and tests; the syntax trees of all 185 Python files are
  unchanged with comments and docstrings removed, frontend sources unchanged), "Prepare the public repository"
  (README, handoff, verification notes) and "Explain why Axiom exists" (README). Clean-clone CI passed on bc2a6aa,
  which contains all code; only README text changed afterwards.

Claims inspected against the code before accepting them:
- The checkpoint-7 statement that a compromised runtime credential "can bind any principal of its tenant" was
  checked against bind_context and the role layout. It was wrong: one runtime login serves every tenant and
  bind_context accepts any tenant and principal. Corrected in ADR 0012 amendment 4.
- The D1/D2 "unauthorised result" wording was checked against the attacker model it assumed; narrowed (same
  amendment).
- The revocation claim was checked against Authorizer.bindings_for (share locks on bindings and memberships only);
  principal status and tenant status are outside it, now documented and tested.
