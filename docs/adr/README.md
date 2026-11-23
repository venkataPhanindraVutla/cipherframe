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
| [0042](0042-deletion-and-retention-details.md) | Deletion and retention details | none (details under P11) | Accepted (flagged for owner review) | 2026-11-14 |
| [0043](0043-subtitle-and-watermark-parameters.md) | Subtitle and watermark parameters | P12 | Accepted | 2026-11-15 |
| [0044](0044-subtitle-tracks.md) | Subtitle tracks | none (details under P12) | Accepted (flagged for owner review) | 2026-11-15 |
| [0045](0045-webhooks.md) | Webhooks: outbox, signing, retries and replay | none (M7-5) | Accepted (flagged for owner review) | 2026-11-15 |
| [0046](0046-thumbnails.md) | Thumbnails: poster, sprite sheet, thumbnail track | none (M7-2) | Accepted (flagged for owner review) | 2026-11-15 |
| [0047](0047-quotas-and-per-client-limits.md) | Quotas and per-client limits | none (M7-6) | Accepted (flagged for owner review) | 2026-11-15 |
| [0048](0048-overlay-watermark-policy.md) | Overlay watermark policy: settings, session code, drift path | none (M7-3, details under P12) | Accepted (flagged for owner review) | 2026-11-15 |
| [0049](0049-brand-logo.md) | Per-tenant brand logo burned in at transcode | none (M7-4) | Accepted (flagged for owner review) | 2026-11-15 |
| [0050](0050-reference-player-approach.md) | Reference player approach | P13 | Accepted | 2026-11-22 |
| [0051](0051-cli-conventions.md) | Command line tool conventions: generated client, auth input, output, exit codes, tus | none (M8-1a, M8-1b) | Accepted (flagged for owner review) | 2026-11-22 |
| [0052](0052-reference-player-implementation.md) | Reference player implementation choices | none (M8-2) | Accepted (flagged for owner review) | 2026-11-22 |
| [0053](0053-observability-stack.md) | Observability stack: OpenTelemetry traces, Prometheus metrics with OTLP push, token-protected `/metrics`, opt-in tenant label | P14 | Accepted | 2026-11-22 |
| [0054](0054-operations-and-release-tooling.md) | Operations and release tooling: Terraform for AWS and GCP, Helm with external Postgres, GoReleaser and cosign keyless, a Go load tool | none (M9) | Accepted | 2026-11-22 |
| [0055](0055-telemetry-implementation.md) | Telemetry implementation choices: hand-rolled HTTP middleware, one global registry, OTLP exporters by environment, metric label sets | none (M9-1a) | Accepted (flagged for owner review) | 2026-11-22 |
| [0056](0056-terraform-example-choices.md) | Terraform example choices: trust policy as input, SSE-S3 default, custom GCS roles, opt-in HMAC keys, fmt and validate in CI | none (M9-3) | Accepted (flagged for owner review) | 2026-11-22 |
| [0058](0058-observability-tooling-and-audit-export.md) | Observability tooling and audit export: dashboard and alerts, observability compose profile, `GET /v1/audit-events`, `cipherframe audit export`, end-to-end secret scan | none (M9-1b) | Accepted (flagged for owner review) | 2026-11-22 |
| [0059](0059-helm-chart-choices.md) | Helm chart choices: secrets as mounted files, flat config map, masker as a worker sidecar, queue-depth KEDA query, fixed ingress prefixes | none (M9-2) | Accepted (flagged for owner review) | 2026-11-22 |
| [0060](0060-release-automation-choices.md) | Release automation choices: images from the existing Dockerfiles, masker job, signing and attestation, no CHANGELOG.md | none (M9-6) | Accepted (flagged for owner review) | 2026-11-22 |
| [0061](0061-load-test-method.md) | Load test method: real-time viewers, ramp until a threshold breaks, raw CSV beside the method | none (M9-4) | Accepted (flagged for owner review) | 2026-11-22 |
| [0062](0062-cdn-signed-urls.md) | CDN signed URLs: CloudFront and Cloud CDN, a `cdn` delivery setting, the presigned expiry rule, purge on deletion | P16 | Accepted | 2026-11-23 |
| [0063](0063-hardware-encoders.md) | Hardware encoders: NVENC, VAAPI, QSV and VideoToolbox per worker, software fallback, only VideoToolbox measured | P17 | Accepted | 2026-11-23 |
| [0064](0064-hevc-and-av1-renditions.md) | HEVC and AV1 renditions: libx265 and SVT-AV1, full ladder per codec, one master with CODECS, per-tenant `extra_codecs` | P18 | Accepted | 2026-11-23 |
| [0065](0065-cdn-implementation.md) | CDN implementation: stdlib signers, key read by edge only, purge job on the worker queued with the tombstone, Cloud CDN purge over REST, Terraform CDN | none (M10-1, details under P16) | Accepted (flagged for owner review) | 2026-11-23 |
| [0066](0066-hardware-encoder-implementation.md) | Hardware encoder implementation: one argument mapping, whole-transcode software retry, probe through rawvideo, a separate dynamically linked `worker-hw` image, VideoToolbox `-q:v` | none (M10-2) | Accepted (flagged for owner review) | 2026-11-23 |
| [0067](0067-hevc-av1-implementation.md) | HEVC and AV1 implementation: setting and per-asset snapshot, worker capability table, one FFmpeg run per codec, `_hevc` and `_av1` rendition names, recorded failure reasons, measured quality settings | none (M10-3) | Accepted (flagged for owner review) | 2026-11-23 |
| [0068](0068-content-key-rekey.md) | Content-key re-key: per-asset job over every variant, generation directories `k<n>/`, sessions bound to a key generation, audit events, flat `rekey` command | none (M10-4) | Accepted (flagged for owner review) | 2026-11-23 |

## Open gates

P19, P20 and P21 (worker). See the build plan's
decision register.
