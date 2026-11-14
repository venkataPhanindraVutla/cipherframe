# Roadmap

Where the build stands, what is left, and what is waiting on a decision. The last pull request of
each milestone updates this page.

Last updated: 2026-11-14.

## Versions

| Version | Theme | Status |
|---|---|---|
| v1.0.0 | The service: ingest, encrypted HLS, playback sessions, key management, integrity, deletion and retention, subtitles, thumbnails, branding, webhooks, quotas, CLI, reference player, operations | In progress (M5) |
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
| M5 Integrity and anchoring | In progress |
| Face masking (ADR 0036) | Done |
| M6 Deletion and retention | Waiting on gate P11 |
| M7 Subtitles, thumbnails, branding, webhooks, quotas | Not started (gate P12) |
| M8 CLI (Go) and reference player (TypeScript) | Not started (gate P13) |
| M9 Operations and release | Not started (gate P14) |
| M10 v1 extras (may slip to v1.1) | Not started (gates P16 to P18) |

### M5 Integrity and anchoring

- [x] M5-1 Per-artifact hashing, Merkle trees, canonical JSON and a signed manifest for every ready
  asset ([integrity.md](integrity.md), [ADR 0033](adr/0033-integrity-design.md))
- [x] M5-2 Signing keys with key IDs and rotation, published at `/.well-known/cipherframe-keys.json`
- [ ] M5-3 Verify API and per-segment proof endpoint
- [ ] M5-4 Public-key-only verifier (library and CLI) with the outcomes "ours", "modified version of
  ours" and "cannot say"
- [ ] M5-5 Optional RFC 3161 anchoring ([ADR 0034](adr/0034-timestamp-authority-recommendations.md))

Acceptance, still to show: flipping one byte fails and names the exact object; verification works
without any signing secret; rotated keys still verify old records; a timestamp token round trip
against a local TSA.

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

- [ ] M6-1 Derived-artifact registry: every artifact kind registers with the purge job
- [ ] M6-2 Verified purge job: delete everything under the asset's prefixes and destroy its content key
- [ ] M6-3 Signed deletion record, fetchable after the asset is gone
- [ ] M6-4 Retention job: per-asset time-to-live and a configurable default
- [ ] M6-5 Privacy settings: storing IP address, user agent and original file name

### M7 Subtitles, thumbnails, branding, webhooks, quotas

- [ ] M7-1 WebVTT subtitles, SRT conversion, transcript import
- [ ] M7-2 Thumbnails: poster, sprite sheet with a WebVTT track, I-frame playlist
- [ ] M7-3 Overlay watermark policy
- [ ] M7-4 Per-tenant brand logo burned in at transcode
- [ ] M7-5 Webhooks (`asset.ready`, `asset.failed`, `asset.deleted`, `session.revoked`,
  `session.anomaly` and more); the `playback_events` outbox already exists
- [ ] M7-6 Quotas and per-client limits

### M8 CLI and reference player

- [ ] M8-1 `cipherframe` CLI in Go, a single static binary
- [ ] M8-2 Reference player in TypeScript on hls.js

### M9 Operations and release

- [ ] M9-1 Observability: traces and metrics across api, edge and worker
- [ ] M9-2 Helm chart
- [ ] M9-3 Terraform example: buckets, IAM, KMS keys
- [ ] M9-4 Load tests with published method and numbers
- [ ] M9-5 Security review: threat model update, fuzz tests for playlist rewriting and token parsing
- [ ] M9-6 Release automation: signed images, SBOM, changelog

### M10 v1 extras

- [ ] M10-1 CDN signed URLs
- [ ] M10-2 Hardware-accelerated encoding with software fallback
- [ ] M10-3 HEVC and AV1 renditions, off by default
- [ ] M10-4 Audited content-key re-key operation

## Open decision gates

Each gate is asked of the project owner and recorded as an ADR before its milestone starts.

| Gate | Decides | Needed for |
|---|---|---|
| P11 | Retention and privacy defaults: asset time-to-live, IP, user agent and original file name storage, access-log retention | M6 |
| P12 | Subtitle and watermark parameters | M7 |
| P13 | Reference player approach | M8 |
| P14 | Observability stack | M9 |
| P16 | CDN providers and cache and revocation policy | M10 |
| P17 | Hardware encoder targets | M10 |
| P18 | HEVC and AV1 policy, including codec licensing | M10 |
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

## Follow-ups

Smaller items found while building, not yet scheduled:

- Allowlist the public test IVs in the golden playlists for the secret scanner.
- Make access-log partition creation work from any role (with M6).
- Rate-limit the viewer-authorization callback and re-wrap its stored secrets on key rotation.
- Let the published key set mark a key "revoked as compromised", not only "retired"
  ([integrity.md](integrity.md)).
