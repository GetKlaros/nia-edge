#!/usr/bin/env bash
# What the CI workflow runs: format, vet, tests with the race detector.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "verify: $1" >&2; exit 1; }

command -v go >/dev/null 2>&1 || fail "go is missing: install the version go.mod names (https://go.dev/dl/)"
required=$(sed -n 's/^go //p' go.mod)
current=$(go env GOVERSION | sed 's/^go//')
[ "$current" = "$required" ] || fail "Go $current is not the $required that go.mod names"

# GOTOOLCHAIN=local: never a toolchain downloaded behind our back.
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
unformatted=$(gofmt -l .)
[ -z "$unformatted" ] || fail "gofmt would change: $unformatted"
go vet ./...
go test -count=1 -race ./...
go build -o /dev/null ./cmd/nia-edge
echo "verify: all steps passed (Go $current)"
