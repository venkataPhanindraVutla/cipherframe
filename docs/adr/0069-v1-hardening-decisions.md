# 0069. v1 hardening: source retention, re-running failed assets, HDR sources, quality setting

- Status: Accepted
- Date: 2026-11-24
- Gate: none (owner decisions before v1.0.0)
- Deciders: project owner

## Context

A review before v1.0.0 found four gaps that cost money or correctness for an adopter:

- The uploaded original stays in the source bucket until the asset is deleted
  ([architecture.md](../architecture.md)). Adopters who already keep their own copy, the common case
  for recorded interviews and calls, store every video twice; the original is larger than the whole
  rendition ladder.
- A `failed` asset can only be deleted ([ADR 0042](0042-deletion-and-retention-details.md)). A failure
  caused by a storage or KMS outage that outlasts the job's retries forces a new upload.
- Sources recorded in HDR (PQ or HLG, BT.2020), which phones produce by default, are scaled as if they
  were SDR and come out washed out.
- The constant-quality values of each codec are compiled in; changing quality needs a rebuild.

## Options considered

- **Source retention:** a per-tenant setting defaulting to keep; the same defaulting to drop; one
  deployment-wide variable.
- **Re-running a failed asset:** an explicit reprocess call; re-opening the asset automatically when its
  dead job is replayed (a failure caused by a bad file would loop).
- **HDR:** tone-map to SDR in the worker (needs the zimg library in the FFmpeg build); reject HDR
  uploads with a clear failure code.
- **Quality setting:** environment variables per codec; a per-tenant setting.

## Decision

1. **H-3 Source retention.** A per-tenant `keep_source` setting, default `true`, so nothing changes for
   existing tenants. It is snapshotted on the asset at upload. When it is `false`, the original is
   deleted once the asset is `ready` and its face masking, if any, is no longer pending. The source hash
   stays in the signed manifest.
2. **H-4 Re-running a failed asset.** An explicit `POST /v1/assets/{asset_id}/reprocess` (scope
   `assets:write`) and `cipherframe reprocess ASSET_ID`, only for a `failed` asset whose original is
   still stored. It is audited and the normal webhooks fire again.
3. **H-2 HDR sources.** Detected in the probe and tone-mapped to 8-bit BT.709 SDR with `zscale` and
   `tonemap`; zimg is added to the worker's FFmpeg builds.
4. **H-1 Quality setting.** `CIPHERFRAME_WORKER_CRF`, `CIPHERFRAME_WORKER_CRF_HEVC` and
   `CIPHERFRAME_WORKER_CRF_AV1`, defaulting to today's 23, 26 and 35.

## Consequences

- With `keep_source` off, changing the ladder or adding a codec later needs a new upload, and a failed
  asset whose original is gone cannot be re-run; the API says so (`source_unavailable`).
- HDR output is SDR: HDR playback is not offered. The FFmpeg build gains one library (WTFPL).
- Implementation details are recorded below as each task merges.

## Implementation

(Added when H-1 to H-4 merge.)
