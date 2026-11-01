#!/usr/bin/env bash
# Warden live tests. Run on your own host, as your normal user, only at a
# commit you have reviewed: the e2e binary runs on the host with Docker
# access, which is root-equivalent.
#
#   scripts/e2e.sh <40-char commit SHA> [repo-url]
#
# 1. Clones the repo fresh into a temp root and checks out exactly that SHA.
# 2. In a Go container (pinned by digest, no network, no capabilities, your
#    UID): gofmt, go vet, unit tests, builds warden and the e2e test binary.
# 3. Runs the e2e binary on the host. Everything lives in the temp root,
#    which is deleted on exit, including on failure.
#
# Nothing is ever pulled. See docs/phase-1.md, "Live tests".
set -euo pipefail

# The Go build image, pinned by digest. Override with GO_IMAGE (also pinned).
GO_IMAGE_PINNED="golang@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9" # golang:1.27-bookworm, from the operator's host

die() { echo "e2e: $*" >&2; exit 1; }

[[ $(id -u) -ne 0 ]] || die "refusing to run as root: run as your normal user"
[[ $# -ge 1 && $# -le 2 ]] || die "usage: scripts/e2e.sh <40-char commit SHA> [repo-url]"
SHA=$1
REPO=${2:-https://github.com/rviscuso/warden}
[[ $SHA =~ ^[0-9a-f]{40}$ ]] || die "need a full 40-character commit SHA, not a branch, tag or short SHA: $SHA"

GO_IMAGE=${GO_IMAGE:-$GO_IMAGE_PINNED}
[[ -n $GO_IMAGE ]] || die "no Go image digest pinned yet: set GO_IMAGE=golang@sha256:<64 hex>"
[[ $GO_IMAGE =~ ^[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] || die "GO_IMAGE must be pinned by digest (name@sha256:<64 hex>), not a tag: $GO_IMAGE"

SOCKET=${WARDEN_E2E_SOCKET:-/var/run/docker.sock}
UID_GID="$(id -u):$(id -g)"

BASE=${XDG_CACHE_HOME:-$HOME/.cache}
mkdir -p "$BASE"
ROOT=$(mktemp -d "$BASE/warden-e2e.XXXXXX")

# Docker as the tests see it: an explicit socket and an empty config, so no
# DOCKER_HOST, context, credential helper or plugin from your setup applies.
export DOCKER_CONFIG="$ROOT/docker-config"
unset DOCKER_HOST DOCKER_CONTEXT
dock() { docker --host "unix://$SOCKET" "$@"; }

cleanup() {
	local status=$?
	if [[ -f $ROOT/containers ]]; then
		while read -r id; do
			[[ -n $id ]] && dock rm -f "$id" >/dev/null 2>&1 || true
		done <"$ROOT/containers"
	fi
	chmod -R u+w "$ROOT" 2>/dev/null || true # Go marks module cache files read-only
	rm -rf "$ROOT"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Siblings, never nested: the workspace never contains a Warden directory.
mkdir -m 700 "$ROOT"/{ws,config,state,share,tmp,gocache,out,docker-config}

dock image inspect "$GO_IMAGE" >/dev/null 2>&1 ||
	die "$GO_IMAGE is not local and nothing is pulled; pull it yourself first: docker pull $GO_IMAGE"

git clone --quiet --no-checkout "$REPO" "$ROOT/src"
git -C "$ROOT/src" -c advice.detachedHead=false checkout --quiet "$SHA"
HEAD=$(git -C "$ROOT/src" rev-parse HEAD)
[[ $HEAD == "$SHA" ]] || die "checked out $HEAD, expected $SHA"
echo "e2e: testing $SHA"
echo "e2e: Go image $GO_IMAGE"

# One container per step, argv only. The source is read-only.
in_go() {
	dock run --rm \
		--network none --user "$UID_GID" --cap-drop ALL \
		--security-opt no-new-privileges --read-only --tmpfs /tmp:exec \
		--pids-limit 512 --memory 1g \
		--volume "$ROOT/src:/src:ro" --volume "$ROOT/gocache:/gocache" --volume "$ROOT/out:/out" \
		--workdir /src \
		--env HOME=/tmp --env GOCACHE=/gocache/build --env GOPATH=/gocache/gopath \
		--env GOFLAGS=-mod=readonly --env GOPROXY=off --env GOTOOLCHAIN=local --env CGO_ENABLED=0 \
		"$GO_IMAGE" "$@"
}

echo "e2e: gofmt -l ."
unformatted=$(in_go gofmt -l .)
[[ -z $unformatted ]] || die "gofmt: unformatted files: $unformatted"
echo "e2e: go vet ./... (and -tags e2e)"
in_go go vet ./...
in_go go vet -tags e2e ./test/e2e
echo "e2e: go test -count=1 ./..."
in_go go test -count=1 ./...
echo "e2e: build"
in_go go build -o /out/warden ./cmd/warden
in_go go test -c -tags e2e -o /out/e2e.test ./test/e2e
grep -c '^require' "$ROOT/src/go.mod" >/dev/null && die "go.mod has require lines"

echo "e2e: live tests on the host"
cd "$ROOT/tmp"
env \
	TMPDIR="$ROOT/tmp" \
	XDG_CONFIG_HOME="$ROOT/config" XDG_STATE_HOME="$ROOT/state" XDG_DATA_HOME="$ROOT/share" \
	WARDEN_E2E_BIN="$ROOT/out/warden" \
	WARDEN_E2E_SHA="$SHA" \
	WARDEN_E2E_GO_IMAGE="$GO_IMAGE" \
	WARDEN_E2E_CONTAINERS="$ROOT/containers" \
	WARDEN_E2E_SOCKET="$SOCKET" \
	WARDEN_E2E_WORKSPACE="$ROOT/ws" \
	"$ROOT/out/e2e.test" -test.v -test.count=1
echo "e2e: all passed at $SHA"
