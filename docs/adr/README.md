# Architecture Decision Records

Process: [0001](0001-record-architecture-decisions.md). New records start from [`template.md`](template.md).

## Decision log

| ADR | Title | Gate | Status | Date |
|---|---|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | none | Accepted | 2026-11-10 |
| [0002](0002-confirmed-baseline-decisions.md) | Confirmed baseline decisions | D1 to D10 | Accepted | 2026-11-10 |
| [0003](0003-repository-owner-and-module-path.md) | Repository owner and Go module path | P1 | Accepted | 2026-11-10 |
| [0004](0004-go-toolchain-bundle.md) | Go toolchain bundle | P3 | Accepted | 2026-11-10 |
| [0005](0005-ci-release-signing-and-sbom.md) | CI platform, release signing and SBOM | P15 | Accepted | 2026-11-10 |
| [0006](0006-repository-layout-and-project-policies.md) | Repository layout and project policies | none | Accepted | 2026-11-10 |
| [0007](0007-datastore-job-queue-and-migrations.md) | Datastore, job queue and migrations | P2 | Accepted | 2026-11-10 |
| [0008](0008-service-topology.md) | Service topology | P4 | Accepted | 2026-11-10 |
| [0009](0009-tenancy-and-api-keys.md) | Tenancy and API keys | P7 (API keys) | Accepted | 2026-11-10 |
| [0010](0010-language-neutral-job-contract.md) | Language-neutral job contract | P21 (contract) | Accepted | 2026-11-10 |
| [0011](0011-id-scheme.md) | ID scheme | none | Accepted | 2026-11-10 |
| [0012](0012-error-model.md) | Error model | none | Accepted | 2026-11-10 |
| [0013](0013-configuration.md) | Configuration | none | Accepted | 2026-11-10 |
| [0014](0014-local-object-storage-and-storage-port.md) | Local object storage and the storage port | none | Accepted | 2026-11-10 |
| [0015](0015-api-conventions-and-contract-test.md) | API conventions and contract test | none | Accepted | 2026-11-10 |
| [0016](0016-api-key-pepper-versioning.md) | API-key pepper versioning | none | Accepted | 2026-11-10 |
| [0017](0017-postgres-version-support.md) | Postgres version support | none | Accepted | 2026-11-10 |
| [0018](0018-management-api-for-clients-and-keys.md) | Management API for clients and keys | none | Accepted (flagged for owner review before v1.0.0) | 2026-11-11 |
| [0019](0019-local-development-key-provider.md) | Local development key provider | P5 | Accepted | 2026-11-11 |
| [0020](0020-envelope-encryption-aead.md) | Envelope encryption AEAD | none | Accepted | 2026-11-11 |
| [0021](0021-vault-transit-test-servers.md) | Vault Transit test servers | none | Accepted | 2026-11-11 |
| [0022](0022-key-provider-packaging.md) | Key provider packaging | none | Accepted | 2026-11-11 |
| [0023](0023-kms-provider-test-strategy.md) | KMS provider test strategy | none | Accepted | 2026-11-11 |
| [0024](0024-encoding-defaults-and-ffmpeg-build.md) | Encoding defaults and FFmpeg build | P8 | Accepted | 2026-11-11 |
| [0025](0025-resumable-uploads-and-media-limits.md) | Resumable uploads and media limits | none | Accepted | 2026-11-11 |
| [0026](0026-asset-and-upload-api.md) | Asset and upload API | none | Accepted (flagged for owner review before v1.0.0) | 2026-11-11 |
| [0027](0027-segment-encryption-in-the-worker.md) | Segment encryption in the worker | none | Accepted (flagged for owner review) | 2026-11-11 |
| [0028](0028-playback-tokens-and-session-parameters.md) | Playback tokens and session parameters | P6 | Accepted | 2026-11-11 |
| [0029](0029-jwt-and-signed-callback-authorization.md) | JWT and signed-callback authorization | P7 (JWT and signed callback) | Accepted | 2026-11-11 |
| [0030](0030-playback-token-transport.md) | Playback token transport | none | Accepted | 2026-11-11 |
| [0031](0031-browser-session-creation-and-jwt-library.md) | Browser session creation and the JWT library | none | Accepted | 2026-11-11 |
| [0032](0032-delivery-strategies.md) | Delivery strategies | none | Accepted (flagged for owner review) | 2026-11-11 |
| [0033](0033-integrity-design.md) | Integrity design | P9 | Accepted (manifest outline flagged for owner review) | 2026-11-12 |
| [0034](0034-timestamp-authority-recommendations.md) | Timestamp authority recommendations | P10 | Accepted | 2026-11-12 |
| [0035](0035-floci-cloud-emulators-in-tests.md) | Floci cloud emulators in tests | none | Accepted | 2026-11-13 |
| [0036](0036-face-masked-variant.md) | Face-masked variant of an asset | P20 (face detection), P21 (worker, face masking) | Accepted (worker placement flagged for owner review) | 2026-11-14 |
| [0037](0037-faster-face-masking.md) | Faster face masking (amends 0024, 0036) | none | Accepted | 2026-11-14 |
| [0038](0038-encoder-preset-and-detection-stride.md) | Encoder preset and detection stride settings (amends 0024, 0036) | none | Accepted | 2026-11-14 |
| [0039](0039-verify-api-proofs-and-offline-verifier.md) | Verify API, proofs and the offline verifier | none | Accepted (flagged for owner review) | 2026-11-14 |
| [0040](0040-retention-and-privacy-defaults.md) | Retention and privacy defaults | P11 | Accepted | 2026-11-14 |
| [0041](0041-rfc-3161-anchoring-of-manifests.md) | RFC 3161 anchoring of manifests | D7 | Accepted (flagged for owner review) | 2026-11-14 |

## Open gates

P12 to P14, P16 to P20, P21 (worker). See the build plan's
decision register.
