#!/bin/sh
# Runs the media and pipeline integration tests (tags integration,media) on a machine where FFmpeg
# is not installed, for example a Mac. FFmpeg only exists as static Linux binaries (built by
# build/worker.Dockerfile), so the whole `go test` runs inside a golang container that
#
#   - has the worker image's static ffmpeg and ffprobe and the test-only generator FFmpeg mounted in,
#   - talks to the host's Docker daemon (socket mounted) so testcontainers can start Postgres and
#     SeaweedFS, and reaches their mapped ports through host.docker.internal.
#
# Usage, from the repository root:
#
#   sh build/test-media.sh                          # go test -tags=integration,media ./internal/...
#   sh build/test-media.sh -run TestPipeline -v ./internal/pipeline/...
#
# Arguments are passed to `go test` after the tags. Environment:
#
#   TOOLS_DIR   directory with ffmpeg, ffprobe and ffmpeg-fixtures (default out/tools). It is built
#               from the Dockerfile's `tools` target when missing or when REBUILD_TOOLS=1.
#   GO_IMAGE    the golang image (default: the digest-pinned one the Dockerfile uses).
set -eu

cd "$(dirname "$0")/.."
root="$(pwd)"

tools="${TOOLS_DIR:-out/tools}"
go_image="${GO_IMAGE:-golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea}"

if [ "${REBUILD_TOOLS:-0}" = 1 ] || [ ! -x "$tools/ffmpeg" ] || [ ! -x "$tools/ffprobe" ] || [ ! -x "$tools/ffmpeg-fixtures" ]; then
	echo "building the FFmpeg binaries (docker build --target tools) into $tools" >&2
	docker build -f build/worker.Dockerfile --target tools --output "type=local,dest=$tools" .
fi
tools_abs="$(cd "$tools" && pwd)"

if [ "$#" -eq 0 ]; then
	set -- ./internal/...
fi

# Named volumes keep the module and build caches between runs.
exec docker run --rm \
	-v "$root":/src -w /src \
	-v "$tools_abs":/tools:ro \
	-v cipherframe-gomod:/go/pkg/mod \
	-v cipherframe-gobuild:/root/.cache/go-build \
	-v /var/run/docker.sock:/var/run/docker.sock \
	--add-host host.docker.internal:host-gateway \
	-e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal \
	-e TESTCONTAINERS_RYUK_DISABLED=true \
	-e CIPHERFRAME_TEST_FFMPEG=/tools/ffmpeg \
	-e CIPHERFRAME_TEST_FFPROBE=/tools/ffprobe \
	-e CIPHERFRAME_TEST_FFMPEG_FIXTURES=/tools/ffmpeg-fixtures \
	-e GOTOOLCHAIN=local \
	${CIPHERFRAME_TEST_PG_IMAGE:+-e CIPHERFRAME_TEST_PG_IMAGE="$CIPHERFRAME_TEST_PG_IMAGE"} \
	"$go_image" \
	go test -count=1 -tags=integration,media "$@"
