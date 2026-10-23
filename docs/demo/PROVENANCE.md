# Screenshots in this folder

All four images come from one run of the demonstration (`scripts/demo/run.sh`, docs/DEMO.md) at commit
`a05c01f7cf81b1bfd162c302cbe1177254bd11f6` on 2026-10-23, finished 12:42:56 UTC. That run's results, lab metadata
and logs are in `docs/verification/2026-10-23-demo-main/`. Chromium (Playwright) took them against a local API,
a local Keycloak and the test database. The tenant, users, cases and digests are synthetic or local to that run.

They were copied from the run's output folder without editing. Each PNG holds only the `IHDR`, `IDAT` and `IEND`
chunks: no text, XMP or Content Credentials metadata.

| File | What it shows | SHA-256 |
|---|---|---|
| `01-investigation-with-the-fake-model.png` | The investigation run, labelled "Fake model (not a language model)", with claims a second analyst reviewed | `b544f69b2e32da620356e48cd6c7782e765bede60f0d98b2054e377eb08801ea` |
| `02-approval-recorded-in-the-ui.png` | A ticket proposal for the local fake tracker, approved in the browser by a different person | `a052947a1d701a6d1c028aad664a1233977abd07709d456a55c501629036b25e` |
| `03-worker-verification-passed.png` | The verification worker's pass for the redeployed digest, before a person closes the case | `8645f22883578b7ad9a39ca1258b59cadf4facc4c3a87054a3032288398132d1` |
| `05-control-A-not-passed.png` | Control A: a change reported against the unchanged deployment, verification failed | `4c0d0b3b84f48fd0778abf7156b374ceff44ff16f233a40661a4544d7e872111` |

Screenshots from earlier runs (21 and 22) were delivered outside the repository and are described in
`docs/verification/2026-10-23-publication/screenshot-provenance.md`.
