# 0060. Release automation choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-6, details under P15)
- Deciders: project owner

## Context

[ADR 0054](0054-operations-and-release-tooling.md) chose GoReleaser with keyless cosign signing and
[ADR 0005](0005-ci-release-signing-and-sbom.md) chose GitHub OIDC provenance and SBOMs. M9-6 turns
that into configuration and leaves several details open.

## Decision

- **Images from the existing Dockerfiles.** GoReleaser's `dockers_v2` builds `build/Dockerfile` and
  `build/worker.Dockerfile` as they are, one multi-platform buildx build per image (linux/amd64 and
  linux/arm64). Both Dockerfiles compile the Go binary inside the build, so the prebuilt binaries in
  GoReleaser's context go unused, and the context lists only the paths the Dockerfiles read (`go.mod`,
  `go.sum`, `cmd`, `internal`, `spec`, `build/worker-SOURCE.md.in`). The image binary is therefore
  compiled a second time, with the same flags and the same `-X` version. The alternative, Dockerfiles
  that copy the prebuilt binary, would make the image binary byte-identical to the archive's but would
  change the development, compose and CI builds. The legacy `dockers` key is deprecated and not used.
- **The masker image is built outside GoReleaser.** It needs the worker image as its FFmpeg source
  (`FFMPEG_IMAGE`), which exists in the registry only after GoReleaser pushes it, so a second job in
  `release.yml` builds `ml/Dockerfile` against the worker's digest, then signs and attests it with
  the same identity. Tags are `<version>` and `latest`. It has no SBOM attestation yet.
- **Signing and attestation.** `cosign sign-blob` signs `checksums.txt` (a Sigstore bundle);
  `cosign sign` signs each image by digest; `actions/attest-build-provenance` records SLSA provenance
  for the archives (through the checksum file) and for each image, pushed to the registry. Image SBOMs
  (syft, SPDX JSON) for the server and worker are attached with `cosign attest` and uploaded to the
  release; archive SBOMs come from GoReleaser's `sboms` step. ADR 0005 also named CycloneDX; only SPDX
  is produced, as the M9-6 brief asks, and CycloneDX can be added as a second syft output.
- **Verification identity** is a regexp on this repository's `release.yml` at a `v*` tag with the GitHub
  Actions OIDC issuer, so a fork or another workflow cannot satisfy it.
- **Version string** is the git tag with its `v` (`{{ .Tag }}`), as the Dockerfiles' `VERSION` argument
  already expects; image tags drop the `v` (`{{ .Version }}`).
- **Changelog.** GitHub releases are the changelog, written by GoReleaser from commit titles since the
  last tag (`changelog.use: github`) and grouped by prefix. No `CHANGELOG.md` is kept. The repository
  merges with merge commits, so the entries are the branch commits (which carry the same milestone
  prefix) rather than the PR titles; squash-merging would make the two equal. `github-native` (true PR
  titles) was not used because it cannot group by title prefix.
- **Release guard.** The workflow fails a tag that is not an ancestor of `origin/main`.
- **Pre-1.0 semver.** Minor releases may break until `v1.0.0`; the breaking-change list is in
  `docs/releasing.md`.
- **CI.** The `release-check` job runs `goreleaser check` and a binaries-only snapshot
  (`--skip=publish,sign,docker,sbom`); images and signing are exercised only by a real tag.
- **GPL.** The worker and masker images are labelled `Apache-2.0 AND GPL-2.0-or-later` and keep the
  source offer in `/usr/share/licenses/ffmpeg/`.

## Consequences

- The first tag is the first real test of the image, signing and attestation steps, which cannot run
  without registry and OIDC access. A pre-release tag such as `v0.1.0-rc.1` is the way to try them.
- A release takes hours because the worker image compiles FFmpeg for the architecture that runs under
  emulation. Layers are not cached between runs; a registry cache could shorten this later.
- Image binaries are rebuilt in the image build, so their bytes can differ from the archives' even
  though the source, flags and version are the same.
