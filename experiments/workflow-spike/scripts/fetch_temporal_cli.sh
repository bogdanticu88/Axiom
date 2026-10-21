#!/usr/bin/env bash
# Download the official Temporal CLI (includes the dev server) into experiments/workflow-spike/.bin/
# The tarball is extracted in a scratch directory, never inside the source tree.
set -euo pipefail
SPIKE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/temporal_cli.tar.gz" \
  "https://temporal.download/cli/archive/latest?platform=linux&arch=amd64"
sha256sum "$TMP/temporal_cli.tar.gz"
tar -tzf "$TMP/temporal_cli.tar.gz"          # expected: LICENSE, temporal
tar -xzf "$TMP/temporal_cli.tar.gz" -C "$TMP" temporal LICENSE
mkdir -p "$SPIKE_DIR/.bin"
install -m 0755 "$TMP/temporal" "$SPIKE_DIR/.bin/temporal"
cp "$TMP/LICENSE" "$SPIKE_DIR/.bin/TEMPORAL_CLI_LICENSE"
"$SPIKE_DIR/.bin/temporal" --version
