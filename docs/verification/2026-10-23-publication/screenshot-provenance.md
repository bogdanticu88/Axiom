# What happened to the seven screenshots in after-checkpoint-8

## Observation
After the session's container restarted on 2026-10-22 at about 21:09 UTC, `sha256sum -c` in
`after-checkpoint-8/` failed for exactly the seven PNG files in `demo/screenshots/`. Every other file matched,
including the bundle, the source archive and the JSON exports. No earlier delivery directory is affected; their
screenshots are inside `.tar.gz` archives, and all their checksums still verify.

## What changed in the files
Each delivered PNG now contains one additional chunk, `caBX` (5,758 bytes), between `IHDR` and the image data.
`caBX` is the PNG container for a C2PA (Content Credentials) manifest. Its readable content names:

* claim generator "Anthropic Files", version 1.0.0, C2PA specification 2.4.0;
* action `com.anthropic.claude.provided`, with the description "Claude provided this file at the request of a user";
* a signing certificate "Anthropic Claude Content Signing", issued by "Anthropic Content Credentials Root CA",
  valid 2026-08-07 to 2028-08-06;
* one manifest URN per file (for example `urn:c2pa:5510d3fe-6a43-4757-914d-a732e1912b16` for
  `03-worker-verification-passed.png`).

Nothing else changed. For all seven files, removing the `caBX` chunk reproduces the original file byte for byte, and
the decoded pixels are identical. The originals were still available in the session workspace where the
demonstration wrote them (`demo-185af5b/screenshots`, written 2026-10-22 20:45 UTC).

## What rewrote them, and when
The delivery directory is not a local disk. It is a remote file store mounted through rclone with a full local
cache. Before the restart, reads were served from the cache, which held the bytes as written, so the checksums
computed at 20:57 UTC matched. After the restart, reads came from the store, which returned the stamped files.

So the chunk was added by the file store's provenance stamping, identified by the manifest itself, at some point
between the write (2026-10-22 20:57:07 UTC) and the first read after the restart (about 21:09 UTC). The manifest
carries no signing time, and no store-side log is available here, so the exact moment, and whether it happens on
upload or later, could not be established. Sending four of the files to the conversation was not the trigger: the
three files that were never sent were stamped in the same way. Only image files were affected.

## Do they still represent the demonstration?
Yes. The pixels are identical to the screenshots the demonstration took at commit `185af5b`. The added manifest
describes how the file was delivered, not what it shows.

## What was done
* The original checksum list in `after-checkpoint-8/SHA256SUMS` had been overwritten on 2026-10-23 at about 00:09
  (UTC+3) with checksums of the stamped files. That hid the change instead of explaining it. It has been restored to
  the original list, which still fails for the seven files, and a `NOTICE.md` there points here.
* This package carries the original screenshot bytes inside `run21-185af5b-screenshots-original.tar.gz`, together
  with both checksum lists for the old directory (`previous-delivery/`).
* New screenshots from a run at the final code revision are inside `run22-b2d2ae1-demo.tar.gz`. No image is
  delivered as a loose file in this package, because the store would stamp it again and break the checksums.
