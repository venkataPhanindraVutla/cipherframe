# Roadmap

Where the build stands, what is left, and what is waiting on a decision. The last pull request of
each milestone updates this page.

Last updated: 2026-11-23.

## Versions

| Version | Theme | Status |
|---|---|---|
| v1.0.0 | The service: ingest, encrypted HLS, playback sessions, key management, integrity, deletion and retention, subtitles, thumbnails, branding, webhooks, quotas, CLI, reference player, operations | In progress (M10; the owner kept all four extras in v1.0.0 on 2026-11-23) |
| v2.0.0 | npm, Go and Python SDKs and verifiers, shared conformance vectors | Not started |
| v2.1.0 | Python ML worker: local speech-to-text, perceptual fingerprint matching, invisible per-asset or per-tenant watermark | Not started |

## v1.0.0 milestones

| Milestone | Status |
|---|---|
| M0 Foundations | Done |
| M1 Core platform | Done |
| M2 Key management | Done |
| M3 Ingest and processing | Done |
| M4 Playback sessions and delivery | Done |
| M5 Integrity and anchoring | Done |
| Face masking (ADR 0036) | Done |
| Faster face masking (ADR 0037) | Done |
| Encoder preset and detection stride (ADR 0038) | Done |
| M6 Deletion and retention | Done ([ADR 0040](adr/0040-retention-and-privacy-defaults.md), [ADR 0042](adr/0042-deletion-and-retention-details.md)) |
| M7 Subtitles, thumbnails, branding, webhooks, quotas | Done (P12 decided, [ADR 0043](adr/0043-subtitle-and-watermark-parameters.md); [ADR 0044](adr/0044-subtitle-tracks.md), [ADR 0045](adr/0045-webhooks.md), [ADR 0046](adr/0046-thumbnails.md), [ADR 0047](adr/0047-quotas-and-per-client-limits.md), [ADR 0048](adr/0048-overlay-watermark-policy.md), [ADR 0049](adr/0049-brand-logo.md)) |
| M8 CLI (Go) and reference player (TypeScript) | Done ([ADR 0050](adr/0050-reference-player-approach.md), [ADR 0051](adr/0051-cli-conventions.md), [ADR 0052](adr/0052-reference-player-implementation.md)) |
| M9 Operations and release | Done (P14 decided, [ADR 0053](adr/0053-observability-stack.md); tooling, [ADR 0054](adr/0054-operations-and-release-tooling.md)) |
| M10 v1 extras | In progress (P16 to P18 decided: [ADR 0062](adr/0062-cdn-signed-urls.md), [ADR 0063](adr/0063-hardware-encoders.md), [ADR 0064](adr/0064-hevc-and-av1-renditions.md); all four extras stay in v1.0.0) |

### M5 Integrity and anchoring

- [x] M5-1 Per-artifact hashing, Merkle trees, canonical JSON and a signed manifest for every ready
  asset ([integrity.md](integrity.md), [ADR 0033](adr/0033-integrity-design.md))
- [x] M5-2 Signing keys with key IDs and rotation, published at `/.well-known/cipherframe-keys.json`
- [x] M5-3 Verify API and per-segment proof endpoint ([ADR 0039](adr/0039-verify-api-proofs-and-offline-verifier.md))
- [x] M5-4 Public-key-only verifier (library and CLI) with the outcomes "ours", "modified version of
  ours" and "cannot say" (`cipherframe verify`, [integrity.md](integrity.md#verifying))
- [x] M5-5 Optional RFC 3161 anchoring ([ADR 0034](adr/0034-timestamp-authority-recommendations.md), [ADR 0041](adr/0041-rfc-3161-anchoring-of-manifests.md))

Acceptance shown by the M5-4 and M5-5 tests: flipping one byte reports `modified` with the exact path;
verification works with public keys only; a rotated and retired key still verifies old records;
unknown key, malformed envelope, unknown path and an unreachable `--keys-url` are "cannot say",
never "modified"; a timestamp token round trip against a local TSA (the asset completes, the anchor job
stores a token, the API returns it, and the offline verifier with the TSA's CA reports `anchored`).

### Face masking

Added 2026-11-14 ([ADR 0036](adr/0036-face-masked-variant.md)). Built before M5-3 to M5-5.

- [x] FM-1 Variants: `mask_faces` on asset creation, one content key per variant, sessions bound to
  a variant
- [x] FM-2 Python masker in `ml/`: claims `media.mask_faces` tasks and blurs faces with YuNet
- [x] FM-3 `asset.mask` job: hand the job directory to the masker, transcode the masked ladder, add it
  to the manifest
- [x] FM-4 Development stack and documentation

Done: an asset created with `mask_faces` gets a masked variant, published by `asset.mask` once the
masker (beside the worker, sharing its work directory) has blurred the source, and listed in the
signed manifest. Still true for M6: the purge job must remove both variants and both content keys,
and any retention of the source object must wait until `masking.state` is no longer `pending`.

### M6 Deletion and retention

- [x] M6-1 Derived-artifact registry: every artifact kind registers with the purge job
- [x] M6-2 Verified purge job: delete everything under the asset's prefixes and destroy its content key
- [x] M6-3 Signed deletion record, fetchable after the asset is gone
- [x] M6-4 Retention job: per-asset time-to-live and a configurable default
- [x] M6-5 Privacy settings: storing IP address, user agent and original file name

Done: `DELETE /v1/assets/{asset_id}` runs the verified purge (`asset.delete`: storage enumerated, not
trusted from the database; both variants; content keys destroyed; storage listed again) and leaves a
signed deletion record that `cipherframe verify --deletion-record` checks offline. An asset can have a
time-to-live (per asset or as a tenant default; none by default), the access trail and anomaly events
are kept for `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS` (90 by default), IP address and user agent stay off
and no original file name is ever stored ([privacy.md](privacy.md)). Details in
[ADR 0042](adr/0042-deletion-and-retention-details.md).

### M7 Subtitles, thumbnails, branding, webhooks, quotas

- [x] M7-1 WebVTT subtitles, SRT conversion, transcript import ([ADR 0044](adr/0044-subtitle-tracks.md))
- [x] M7-2 Thumbnails: poster, sprite sheet with a WebVTT track ([ADR 0046](adr/0046-thumbnails.md); no I-frame playlist, the reason is in the ADR)
- [x] M7-3 Overlay watermark policy: tenant settings, session code with a lookup through the access trail, the
  `overlay` object in every session response, deterministic drift with conformance vectors
  ([ADR 0048](adr/0048-overlay-watermark-policy.md))
- [x] M7-4 Per-tenant brand logo burned in at transcode ([ADR 0049](adr/0049-brand-logo.md); not retroactive, worker images must be rebuilt)
- [x] M7-5 Webhooks (`asset.ready`, `asset.failed`, `asset.deleted`, `session.revoked`,
  `session.anomaly`, `retention.expired`): outbox written by triggers, Standard Webhooks signing,
  retries over about a day, dead-letter list and replay API ([ADR 0045](adr/0045-webhooks.md))
- [x] M7-6 Quotas and per-client limits: storage bytes, monthly transcode minutes, concurrent sessions
  and request rates per tenant with lower per-client overrides, an admin API and a usage endpoint
  ([ADR 0047](adr/0047-quotas-and-per-client-limits.md))

### M8 CLI and reference player

- [x] M8-1 `cipherframe` CLI in Go, a single static binary: assets, sessions, `verify-file`, `proof`, subtitles, brand, keys and webhooks ([ADR 0051](adr/0051-cli-conventions.md); `session list` and `keys rewrap` have no API call, see the ADR)
- [x] M8-2 Reference player in TypeScript on hls.js ([ADR 0052](adr/0052-reference-player-implementation.md), `player/`)

### M9 Operations and release

- [x] M9-1 Observability: traces and metrics across api, edge and worker
  - [x] M9-1a: telemetry core, [observability.md](observability.md), [ADR 0055](adr/0055-telemetry-implementation.md)
  - [x] M9-1b: Grafana dashboard, alert rules with `promtool` tests, the `observability` compose profile, `GET /v1/audit-events` and `cipherframe audit export`, the end-to-end secret scan ([ADR 0058](adr/0058-observability-tooling-and-audit-export.md), `deploy/observability/`)
- [x] M9-2 Helm chart ([ADR 0059](adr/0059-helm-chart-choices.md), `deploy/helm/cipherframe/`; external Postgres only per [ADR 0054](adr/0054-operations-and-release-tooling.md); rendered and schema-checked in CI, no cluster install test)
- [x] M9-3 Terraform example: buckets, IAM, KMS keys ([ADR 0056](adr/0056-terraform-example-choices.md), `deploy/terraform/`)
- [x] M9-4 Load tests with published method and numbers ([load-tests.md](load-tests.md), [ADR 0061](adr/0061-load-test-method.md), `cmd/cipherframe-load`, raw CSVs in `docs/load-results/`)
- [x] M9-5 Security review: threat model update, fuzz tests for playlist rewriting, token, key and subtitle parsing (CI `fuzz` job on pushes to main), [disaster recovery](disaster-recovery.md)
- [x] M9-6 Release automation: signed images, SBOM, changelog ([ADR 0060](adr/0060-release-automation-choices.md), [releasing.md](releasing.md), `.goreleaser.yaml`)

### M10 v1 extras

- [x] M10-1 CDN signed URLs ([ADR 0062](adr/0062-cdn-signed-urls.md), [ADR 0065](adr/0065-cdn-implementation.md), [cdn.md](cdn.md), `internal/cdn`)
- [ ] M10-2 Hardware-accelerated encoding with software fallback
- [ ] M10-3 HEVC and AV1 renditions, off by default
- [ ] M10-4 Audited content-key re-key operation

## Open decision gates

Each gate is asked of the project owner and recorded as an ADR before its milestone starts.

| Gate | Decides | Needed for |
|---|---|---|
| P19 | SDK package names, scopes and minimum language versions | v2.0.0 |
| P20 | ML models and their licences (face detection decided in ADR 0036) | v2.1.0 |
| P21 | How the Python ML worker consumes jobs (face masking decided in ADR 0036) | v2.1.0 |

## Decisions flagged for owner review before v1.0.0

These were accepted to keep the build moving and should be confirmed before the release:

- [ADR 0018](adr/0018-management-api-for-clients-and-keys.md) Management API for clients and keys
- [ADR 0026](adr/0026-asset-and-upload-api.md) Asset and upload API
- [ADR 0027](adr/0027-segment-encryption-in-the-worker.md) Segment encryption in the worker
- [ADR 0032](adr/0032-delivery-strategies.md) Delivery strategies
- [ADR 0033](adr/0033-integrity-design.md) Integrity design: the manifest outline
- [ADR 0036](adr/0036-face-masked-variant.md) Face-masked variant: the masker runs beside the Go worker
- [ADR 0039](adr/0039-verify-api-proofs-and-offline-verifier.md) Verify API, proofs and the offline verifier
- [ADR 0041](adr/0041-rfc-3161-anchoring-of-manifests.md) RFC 3161 anchoring of manifests (`CIPHERFRAME_TSA_URL`, job `manifest.anchor`, `GET .../manifest/timestamp`)
- [ADR 0037](adr/0037-faster-face-masking.md) Faster face masking: `asset.mask` runs beside `asset.process`; configurable ladder
- [ADR 0038](adr/0038-encoder-preset-and-detection-stride.md) Encoder preset (`CIPHERFRAME_WORKER_X264_PRESET`) and detection stride (`CIPHERFRAME_ML_DETECT_EVERY`)
- [ADR 0042](adr/0042-deletion-and-retention-details.md) Deletion and retention details: the `deleting` state, tombstone reads, purge order, `not_deleted`, time-to-live rules
- [ADR 0047](adr/0047-quotas-and-per-client-limits.md) Quotas and per-client limits: unlimited by default, where each limit is enforced, the per-instance request rate limit
- [ADR 0055](adr/0055-telemetry-implementation.md) Telemetry implementation: hand-rolled HTTP middleware, metric label sets, scrape token rules
- [ADR 0056](adr/0056-terraform-example-choices.md) Terraform examples: trust policy as input, SSE-S3 default, looser GCS roles than AWS
- [ADR 0058](adr/0058-observability-tooling-and-audit-export.md) Observability tooling and `GET /v1/audit-events`
- [ADR 0059](adr/0059-helm-chart-choices.md) Helm chart: masker as a worker sidecar, flat config map, KEDA query
- [ADR 0060](adr/0060-release-automation-choices.md) Release automation: images compile Go in the Dockerfile, no CHANGELOG.md, SPDX only
- [ADR 0061](adr/0061-load-test-method.md) Load test method
- [ADR 0065](adr/0065-cdn-implementation.md) CDN implementation: signing key read by edge only, purge job on the worker, Cloud CDN purge over REST, Terraform CDN

## Follow-ups

Smaller items found while building, not yet scheduled:

- Share the request rate limit across api instances if a per-instance limit proves too loose
  ([ADR 0047](adr/0047-quotas-and-per-client-limits.md)).
- Allowlist the public test IVs in the golden playlists for the secret scanner.
- Give `audit_events` and `playback_sessions` a retention window (not covered by ADR 0040; see ADR 0042).
- Have the retention sweep also create the access-log partitions, so a deployment without the edge role
  keeps them (the edge sweeper does it today).
- Let the retention job page past expired assets it cannot queue: today it always reads the 100
  oldest, so 100 that keep failing would hold back the rest.
- Retry an `asset.delete` job on storage errors that look final (for example a missing bucket):
  today such an error cancels the job, and the asset stays `deleting` until `DELETE` is repeated.
- Check the sprite sheet's last tile at interval boundaries: if FFmpeg's frame rounding and the
  track's tile count disagree by one, the last thumbnail cue can point at a blank padded tile.
- Rate-limit the viewer-authorization callback and re-wrap its stored secrets on key rotation.
- Let the published key set mark a key "revoked as compromised", not only "retired"
  ([integrity.md](integrity.md)).
- Recover signing when the wrapped signing-key seeds are lost but the database survives: today the
  service creates a key only when none exists, so signing fails closed until a key is added by hand
  ([disaster-recovery.md](disaster-recovery.md#losing-the-signing-keys)).
- Make restoring a backup safe for deletions: after a restore, replay the signed deletion records so
  assets deleted since the backup are deleted again ([disaster-recovery.md](disaster-recovery.md)).
- Fuzz the tus library's `Upload-Metadata` handling at the edge request level (Cipherframe discards the
  values, but the third-party parser runs first).
