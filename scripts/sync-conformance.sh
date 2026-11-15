#!/usr/bin/env bash
# Refreshes conformance/*.json from the cases the Nia server generated.
#   scripts/sync-conformance.sh /path/to/nia/conformance
set -euo pipefail
cd "$(dirname "$0")/.."
source_dir=${1:?usage: scripts/sync-conformance.sh <directory of the server's cases>}
for name in canonical.json decisions.json; do
  [ -f "$source_dir/$name" ] || { echo "sync-conformance: $source_dir/$name is missing" >&2; exit 1; }
  cp "$source_dir/$name" "conformance/$name"
done
git status --short conformance
