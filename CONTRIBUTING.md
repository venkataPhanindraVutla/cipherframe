# Contributing to Cipherframe

Thank you for helping. Please read this whole page before opening a pull request.

## Ground rules

- Be kind. Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report security issues privately. See [SECURITY.md](SECURITY.md).
- Contributions are licensed under [Apache-2.0](LICENSE). By submitting a contribution you agree to
  license it under those terms.
- Write original code. Do not paste code from other projects unless its licence is compatible
  (see below) and its origin and licence are recorded in the pull request.

## Decisions come first

Cipherframe records every design decision as an ADR in [`docs/adr/`](docs/adr/). If your change
introduces a real choice (a new dependency, a schema shape, a default value, a public API name), open
an issue or a draft ADR first and wait for agreement before building on it.

## Invariants

Pull requests that break any of these are not merged:

1. **FFmpeg and FFprobe always run as separate processes.** Never link them as libraries, never use
   cgo bindings to libav*, never invoke them through a shell. Use argument arrays only.
2. One canonical rendition set per asset. No per-viewer derivative media.
3. Per-viewer identification is a client-side overlay only.
4. The source object is never browser-addressable, and its storage key never appears in a response.
5. Deletion enumerates storage, destroys content keys (rows are destroyed, not flagged), re-lists to
   confirm, and signs a record. Every derived artifact is registered with the purge job.
6. One active content key per asset.
7. Never claim that video "cannot be downloaded". HLS AES-128 is not DRM.
8. Security failures fail closed. Unknown errors are never reported as success or as tampering.
9. No secrets, tokens, key material, signed URLs or source object keys in logs, traces, errors, URLs
   or test output.

## Dependency licence policy

New dependencies must use one of these licences: **Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC,
MPL-2.0**. CI enforces this with `go-licenses`. Anything else (including all GPL and AGPL variants
and unlicensed code) needs an ADR first.

FFmpeg is a runtime tool, not a dependency, and is never linked (rule 1 above).

## Workflow

1. One branch per task, named after the task ID: `feat/m4-03-key-endpoint`, `fix/...`, `docs/...`.
2. Small commits with clear messages (`area: what changed`).
3. Every change ships with tests and documentation. A task is done only when an automated test proves
   its acceptance criteria.
4. Documentation must be honest: each security feature states what it does **not** protect against.
5. Merge only when CI is green.

## Local checks

Requires Go 1.27. Run everything CI runs before pushing:

```sh
gofumpt -l .            # must print nothing
golangci-lint run
go vet ./...
go test -race ./...
govulncheck ./...
go-licenses check ./... --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
gitleaks git --redact
sqlc diff               # generated code in internal/db/dbgen must be current
```

Database tests need Docker and run with the `integration` build tag. They start Postgres through
testcontainers; set `CIPHERFRAME_TEST_PG_IMAGE` (default `postgres:18.6`) to test another version:

```sh
go test -race -tags=integration ./internal/db/...
CIPHERFRAME_TEST_PG_IMAGE=postgres:16.15 go test -race -tags=integration ./internal/db/...
```

After changing a migration or a query in `internal/db/queries/`, run `sqlc generate` and commit the
result.

### Media and pipeline tests

The tests tagged `media` run the real FFmpeg and FFprobe, and the pipeline test
(`internal/pipeline`, tags `integration,media`) also needs Postgres and SeaweedFS. FFmpeg only exists
as static Linux binaries built by `build/worker.Dockerfile`, so on a Mac (or anywhere without
FFmpeg) the whole `go test` runs inside a Linux container:

```sh
sh build/test-media.sh                                              # go test -tags=integration,media ./internal/...
sh build/test-media.sh -run TestPipeline -v ./internal/pipeline/    # only the pipeline tests, verbose
REBUILD_TOOLS=1 sh build/test-media.sh ...                          # rebuild the binaries after changing the Dockerfile
```

The script builds the Dockerfile's `tools` target into `out/tools` (the shipped `ffmpeg` and
`ffprobe` plus `ffmpeg-fixtures`, the test-only generator that also has the `ssim` and `psnr`
filters; those filters are never in the shipped build), then runs `go test` in the pinned `golang`
image with the binaries mounted, the host's Docker socket mounted, and
`TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal` so testcontainers can reach the Postgres and
SeaweedFS containers it starts. The first run builds FFmpeg (several minutes, cached after that) and
downloads the Go modules into two Docker volumes. The 20 second pipeline fixture takes about 25
seconds to process and verify.

On a Linux machine with Docker you can skip the container: extract the binaries, put them on `PATH`
and run `go test` directly, which is what the `media` CI job does.

```sh
docker build -f build/worker.Dockerfile --target tools --output type=local,dest=out/tools .
CIPHERFRAME_TEST_FFMPEG=$PWD/out/tools/ffmpeg CIPHERFRAME_TEST_FFPROBE=$PWD/out/tools/ffprobe \
  CIPHERFRAME_TEST_FFMPEG_FIXTURES=$PWD/out/tools/ffmpeg-fixtures \
  go test -race -tags=integration,media ./internal/...
```

The lint, vet, vulnerability and licence checks run with `-tags=integration,media` so the tagged files
are checked too:

```sh
golangci-lint run --build-tags=integration,media ./...
go vet -tags=integration,media ./...
govulncheck -tags=integration,media ./...
GOFLAGS=-tags=integration,media go-licenses check ./... --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
```

Tool versions are pinned in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
