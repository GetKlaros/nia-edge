#!/usr/bin/env bash
# Builds the release binaries of one version, and their checksums.
#
#   scripts/release.sh v0.1.0            builds dist/ from the tag v0.1.0
#
# The tag must exist and be the commit checked out, with nothing modified:
# what is published is exactly what the tag names. The builds are static
# (CGO_ENABLED=0) and reproducible: the same tag and the same Go version give
# the same bytes, so anyone can rebuild a binary and compare its checksum.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "release: $1" >&2; exit 1; }

version=${1:?usage: scripts/release.sh <tag, for instance v0.1.0>}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "$version is not a version like v0.1.0"
[ -z "$(git status --porcelain)" ] || fail "the working tree has changes: a release is built from a clean tag"
tagged=$(git rev-parse -q --verify "refs/tags/$version^{commit}") || fail "no tag $version"
[ "$tagged" = "$(git rev-parse HEAD)" ] || fail "tag $version is not the commit checked out"

required=$(sed -n 's/^go //p' go.mod)
current=$(go env GOVERSION | sed 's/^go//')
[ "$current" = "$required" ] || fail "Go $current is not the $required that go.mod names"

scripts/verify.sh

rm -rf dist
mkdir dist
export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name="nia-edge_${version#v}_${os}_${arch}"
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=${version#v}" -o "dist/$name" ./cmd/nia-edge
  echo "built dist/$name"
done
# The installer and its firewall rule go with the Linux binaries.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git log -1 --format=%ct)" \
  -czf "dist/nia-edge_${version#v}_install-linux.tar.gz" install/linux.sh install/firewall-linux.sh
(cd dist && sha256sum -- * > SHA256SUMS)
echo
cat dist/SHA256SUMS
