# Releasing Cipherframe

Releases are cut by pushing a `vX.Y.Z` tag. [`.github/workflows/release.yml`](../.github/workflows/release.yml)
runs GoReleaser ([`.goreleaser.yaml`](../.goreleaser.yaml)) and publishes binaries, container images, SBOMs,
signatures and provenance. The tools are chosen in [ADR 0005](adr/0005-ci-release-signing-and-sbom.md),
[ADR 0054](adr/0054-operations-and-release-tooling.md) and [ADR 0060](adr/0060-release-automation-choices.md).

## What a release contains

| Artifact | Where | Notes |
| --- | --- | --- |
| `cipherframe_<version>_<os>_<arch>` archives | GitHub release | CLI for linux, darwin, windows on amd64 and arm64. Static, `CGO_ENABLED=0`, `-trimpath`. `.zip` on Windows, `.tar.gz` elsewhere. |
| `cipherframe-server_<version>_linux_<arch>.tar.gz` | GitHub release | The server binary for linux amd64 and arm64. |
| `checksums.txt`, `checksums.txt.sigstore.json` | GitHub release | SHA-256 of every archive and the keyless signature bundle over that file. |
| `*.spdx.json` | GitHub release | SPDX SBOM of each archive (syft), and of the server and worker images. |
| `ghcr.io/<owner>/cipherframe-server` | ghcr.io | api and edge roles, no FFmpeg. linux/amd64 and linux/arm64. |
| `ghcr.io/<owner>/cipherframe-worker` | ghcr.io | Server plus static FFmpeg. linux/amd64 and linux/arm64. GPL, see below. |
| `ghcr.io/<owner>/cipherframe-ml` | ghcr.io | The face masker, built on the worker image's FFmpeg. Signed and attested; no SBOM yet. |

Images carry the tags `<version>` (no `v`) and `latest` (stable releases only, not pre-releases), and
the OCI labels `source`, `revision`, `version`, `created` and `licenses`. A tag with a suffix such as
`v1.2.0-rc.1` is published as a GitHub pre-release. The player's npm package (`player/`) has its own
version and is not part of this workflow.

## Versioning policy

Cipherframe follows [Semantic Versioning](https://semver.org). The version is the tag, and the binaries
report it (`cipherframe --version`). Until `v1.0.0`, a minor release may contain breaking changes,
which the notes call out; from `v1.0.0` they need a major release.

A change is **breaking** when an existing, correct deployment or client stops working or changes
behaviour without being edited:

- **HTTP API** (`spec/openapi.yaml`): removing or renaming a path, field, enum value or error `type`;
  tightening validation; making an optional field required; changing a status code or the meaning of
  a field. Adding optional fields, endpoints or enum values is not breaking, so clients must ignore
  unknown fields.
- **CLI**: removing or renaming a command or flag, changing a default, the `--json` output, or an
  exit code (the documented codes in [ADR 0051](adr/0051-cli-conventions.md)).
- **Configuration**: removing or renaming an environment variable, a `_FILE` variant or a role, or
  changing a default so that behaviour differs.
- **On-disk and stored formats**: object layout in storage, the wrapped content-key envelope, the
  work directory layout, anything an older binary would misread.
- **Manifest and record formats**: playlists and manifests served to players, session tokens, the signed
  deletion record and proof formats that `verify-file` and the public verifier read. A new record
  version that old verifiers reject is breaking.
- **Database migrations**: a migration that cannot run while the previous version is still serving,
  that drops or rewrites data, or that is not applied by `--migrate`. Expand-then-contract changes
  are not breaking.

A release that breaks anything above has a `!` after the prefix of the PR title (`M12-1!: ...`) so it
lands under "Breaking changes" in the notes, and the PR description states the upgrade steps.
Security fixes are patch releases.

## Cutting a release

1. Make sure `main` is green and every merged PR title says what changed (see Release notes).
2. Check the commits since the last tag against the breaking-change list above and pick the version.
3. Tag the commit on `main` and push the tag:
   ```sh
   git switch main && git pull --ff-only
   git tag -s v1.2.3 -m "v1.2.3"      # or an annotated tag without -s
   git push origin v1.2.3
   ```
4. Watch the `release` workflow. It refuses a tag that is not on `main`. The worker image compiles FFmpeg
   for two architectures (one of them under emulation), so expect a long run.
5. Verify the artifacts as a user would (below), then edit the release notes if they need a summary.

If the workflow fails after the images were pushed, fix forward with a new patch tag; do not move or
delete a published tag. Try the first release with a pre-release tag such as `v0.1.0-rc.1`.

CI has a `release-check` job that runs `goreleaser check` and a binaries-only snapshot build on every pull
request, so the configuration cannot rot. To try it locally (it needs `GITHUB_REPOSITORY` and
`GITHUB_REPOSITORY_OWNER` set, which GitHub Actions does for you):

```sh
goreleaser release --snapshot --clean --skip=publish,sign,docker,sbom
```

### Release notes and CHANGELOG

GoReleaser writes the release notes from the commit titles since the previous tag, grouped by prefix:
`!` or `BREAKING CHANGE` (Breaking changes), a milestone id such as `M9-6` or `feat` (Features and
milestones), `fix`, `docs` or `ADR`, and everything else. Merge commits are left out. When a PR is
squash-merged its title is the commit title, so write PR titles for a reader of the release page. No
`CHANGELOG.md` file is kept in the repository: the GitHub releases are the changelog, which avoids a
second copy to keep in step ([ADR 0060](adr/0060-release-automation-choices.md)).

## Verifying a release

The signing identity is this repository's release workflow, run by GitHub Actions, so there is no
public key to fetch. Install [cosign](https://docs.sigstore.dev/cosign/) and the
[GitHub CLI](https://cli.github.com). Replace `OWNER` with the repository owner (`OWNER_LC` is the same
in lower case, as ghcr.io requires) and use the version you downloaded.

### An image

```sh
IMAGE=ghcr.io/OWNER_LC/cipherframe-server:1.2.3        # or cipherframe-worker, cipherframe-ml

cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github\.com/OWNER/cipherframe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://$IMAGE" --repo OWNER/cipherframe    # SLSA build provenance

cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/OWNER/cipherframe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com    # the SBOM (server and worker)
```

The regexp pins the workflow file and a version tag; a signature made by a fork, another workflow or a
branch does not match. For production, pin the image by the digest that `cosign verify` reports
instead of the tag.

### A binary

```sh
sha256sum --check --ignore-missing checksums.txt            # shasum -a 256 -c on macOS

cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/OWNER/cipherframe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify cipherframe_1.2.3_linux_amd64.tar.gz --repo OWNER/cipherframe
```

The first two commands show the archive is the one listed in the signed checksum file; the last shows
the build provenance names this repository's workflow and the tagged commit.

## Reproducible builds

**Reproducible.** The Go binaries. A build with the same Go toolchain, the same commit and the same
`go.sum` gives byte-identical binaries: GoReleaser sets `-trimpath`, strips with `-s -w`, injects only
the tag as the version, builds with `CGO_ENABLED=0` and stamps files with the commit time
(`mod_timestamp`). To check, check out the tag and run the snapshot command above; the binaries are
in `dist/cli_*/` and `dist/server_*/`. Compare binaries, not `.tar.gz` files, which can differ between
GoReleaser versions. Use the Go version in `go.mod` and `.github/workflows/ci.yml`.

**Not fully reproducible.**

- **FFmpeg in the worker image.** Every source download is pinned by SHA-256 and the toolchain comes
  from a fixed `snapshot.debian.org` date, but FFmpeg and x264 are compiled inside the image build, and
  the result is not guaranteed to be bit-for-bit identical across build machines. Rebuild from
  `build/worker.Dockerfile` to get an equivalent binary, and compare `ffmpeg -buildconf`.
- **Image layers.** Image digests differ between builds (file timestamps, layer metadata). The
  signature and provenance are over the digest that was published; verify that digest. The server
  binary inside an image is compiled again in the image build, so it is built from the same source and
  flags as the archive's but is not guaranteed to have the same bytes.
- **The masker image.** It installs Python wheels from `uv.lock` (hashes pinned) and downloads the face
  model (SHA-256 checked), but its Python base image tag moves with upstream updates.
- **Base images** of the Go and worker images are pinned by digest in the Dockerfiles and updated by
  pull request, so a tag records exactly which ones it used.

## Licensing of the worker image (GPL)

The worker image contains FFmpeg and x264, which are licensed under the GNU General Public License
(FFmpeg is built with `--enable-gpl`), next to Cipherframe's Apache-2.0 server binary. They are
separate programs that the server starts as processes; they are not linked into it. The image's
`org.opencontainers.image.licenses` label reads `Apache-2.0 AND GPL-2.0-or-later` for that reason, and
the same holds for the masker image, which copies the FFmpeg binary out of the worker image. The
server image and the Go archives contain no GPL code.

Redistributors of the worker or masker image carry the GPL obligations for those binaries. The image
includes the licence texts and a written source offer in `/usr/share/licenses/ffmpeg/` (`SOURCE.md`,
generated from `build/worker-SOURCE.md.in` with the exact versions, source URLs and SHA-256 pins, and
the `configure` line). When changing the release tooling, keep the source offer in the image and do
not publish a worker image built without it.
