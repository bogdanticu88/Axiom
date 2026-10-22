# Starting point check (checkpoint 5), 2026-10-22 ~13:25Z
- Working tree clean; HEAD 622f216 = tag checkpoint-5 (annotated tag object df1a6a82).
- Delivered artifacts: sha256sum -c SHA256SUMS -> all 5 OK (bundle, screenshots, review package, source archive, MANIFEST).
- Bundle clones; tag checkpoint-5 -> 622f216b155b48fb70581af564dc44d011a46735.
- Clean-clone CI PASS was on 3e95d461c7cc4f59686d4b07f33835b723c29b79 (input-manifest.txt), tree 4c2384cb.
- 3e95d46..622f216 changes 12 files, all under docs/ (2 docs files + 10 under docs/verification/2026-10-22-checkpoint5); 0 files outside docs. Documentation-only: confirmed.
- Source archive contents identical to the tag tree (diff -r).
- CI log: 453 passed, 2 skipped (physical drill run as separate stage; opt-in real-provider test); 6 browser, 8 SSO, 13 OIDC unit tests passed. ERROR lines in the log are captured log output from passing negative tests (tamper detection, failing job steps), not test errors.
- Review package: internal SHA256SUMS OK; no raw credential-shaped text.
- DISCREPANCY: the checkpoint-5 chat report listed two checksums against the wrong files. It gave c97926fa... for the source archive and c1b05b4d... for the screenshots; SHA256SUMS (correct) has c97926fa... = analyst-ui-screenshots.tar.gz and c1b05b4d... = axiom-source-checkpoint-5-20261022T1215Z.tar.gz. The files and SHA256SUMS are right; the chat text was wrong.
- FINDING (local workspace, not the delivered artifacts): the checkpoint-5 mutation harness left a stale, mutated
  bytecode file. Mutation M8 replaced `downgrades.append(` with `(lambda *a: None)(` (same length); the restore wrote
  the original source back with a size and whole-second mtime equal to the mutated file's, so Python kept using the
  mutated claims.cpython-313.pyc. Symptom: test_same_reported_scan_time... failed locally on unchanged checkpoint-5
  code. Clearing __pycache__ fixed it. Checkpoint-5 CI ran on a fresh clone (no __pycache__), and the 444-test local
  run happened before the mutation runs, so the recorded results stand; but the harness was unsafe. Fixed in the
  checkpoint-6 harness (no bytecode writes, cache purge, full sanity run after restore).
