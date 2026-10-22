#!/usr/bin/env bash
# Verify that every `uses: owner/repo@<sha> # <tag>` in .github/workflows resolves, in the official repository, to
# exactly that commit for that tag, and that no action is referenced by a mutable tag or branch.
#   scripts/ci/check-action-pins.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0
while IFS= read -r line; do
  ref=$(sed -E 's/.*uses: *([^ ]+).*/\1/' <<<"$line"); tag=$(sed -nE 's/.*# *(v[0-9][^ ]*).*/\1/p' <<<"$line")
  repo=${ref%@*}; sha=${ref#*@}
  if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then echo "FAIL $repo: not pinned to a full commit hash ($sha)"; fail=1; continue; fi
  if [ -z "$tag" ]; then echo "FAIL $repo@$sha: no '# vX.Y.Z' comment naming the tag"; fail=1; continue; fi
  got=$(git ls-remote "https://github.com/$repo.git" "refs/tags/$tag" "refs/tags/$tag^{}" | sort -k2 | tail -1 | cut -f1)
  if [ "$got" = "$sha" ]; then echo "ok   $repo $tag $sha"; else echo "FAIL $repo $tag: pinned $sha, tag is ${got:-missing}"; fail=1; fi
done < <(grep -rhE '^\s*-?\s*uses:' "$ROOT/.github/workflows")
exit $fail
