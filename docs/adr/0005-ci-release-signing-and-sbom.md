# 0005. CI platform, release signing and SBOM

- Status: Accepted
- Date: 2026-11-10
- Gate: P15
- Deciders: project owner

## Context

M0-3 needs CI for format, lint, vet, unit tests, race detector, vulnerability scan, licence check and
secret scanning. M9-6 and V2-6 need signed images, SBOMs and provenance without long-lived publishing
tokens.

## Options considered

1. **GitHub Actions with Sigstore keyless signing**: identity comes from the workflow's OIDC token;
   there is no signing key to protect.
2. **GitHub Actions with a cosign key pair held by the owner**: verification works without the public
   Sigstore transparency log (useful for air-gapped users), but the key must be protected and rotated.
3. **A different CI platform**.

## Decision

Option 1:

| Concern | Choice |
|---|---|
| CI | GitHub Actions |
| Checks on every push and PR | `gofumpt` check, `golangci-lint` v2, `go vet`, `go test -race`, `govulncheck`, licence check (`go-licenses`), secret scan (`gitleaks`) |
| Release build | GoReleaser |
| Signing | `cosign` keyless (Sigstore, GitHub OIDC) for container images and checksum files |
| Provenance | SLSA build provenance attestations from GitHub Actions |
| SBOM | Syft, in both SPDX and CycloneDX, attached to each release and image |

## Consequences

- No signing secret lives in the repository or in CI secrets.
- Verifying a release needs the Sigstore public-good infrastructure (Rekor, Fulcio roots). Air-gapped
  verification is not covered; if it becomes a requirement, a held-key option can be added later.
- Integration and e2e jobs are added to CI as the milestones that need them land.
- This ADR does not cover npm/PyPI publishing; that is V2-6 (trusted publishing, no long-lived tokens).
