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

Accepted (flagged for owner review): the choices below were made while building and were not asked.

**H-1 (CRF variables).** The values are applied to every rung through `media.CRFs`; hardware encoders
map them as before. With the defaults the FFmpeg arguments are byte-identical to the earlier build. The
signed manifest already records each rung's CRF, so its format is unchanged.

**H-2 (HDR).** A source is HDR when its transfer is `smpte2084` (PQ) or `arib-std-b67` (HLG); BT.2020
primaries with an SDR transfer get a primaries-only conversion. The conversion runs once, after `fps`
and before the split, so every rendition, the poster and the sprite share it; an HDR file without
primaries or matrix tags is assumed BT.2020. The worker's capability check requires `zscale` and
`tonemap`, so an operator's own FFmpeg without them fails at startup instead of on the first HDR
upload. The masker makes an SDR copy first for HDR and wide-gamut sources (it now needs ffprobe), so
the `media.mask_faces` contract is unchanged. zimg 3.0.5 is pinned by SHA-256; the fixtures FFmpeg
gets a 10-bit x264 to make HDR test files, while the shipped x264 stays 8-bit.

**H-3 (`keep_source`).** In `PUT /v1/privacy-settings` the field is optional and a missing value means
`true`, so an older client cannot switch it off by accident. The snapshot is taken at asset create. The
`asset.drop_source` job is queued in the transaction that makes the asset ready (or settles its
masking), deletes the whole source prefix (original, tus metadata and parts), then records
`source_deleted_at` and the `asset.source_deleted` audit event. A dropped source stops counting
toward the storage quota.

**H-4 (reprocess).** The content key is reused: only a purge destroys keys, and retries already reuse
it. The new run removes the failed run's partial output itself, as every run does. There is no quota
check at request time (the duration is unknown until the probe); the failed run's transcode charge is
removed, so the new run charges again and can fail with `quota_transcode_minutes`. A request while a
job of the earlier run is still active is `conflict`; an aborted upload is `source_unavailable`. The
state is checked before the source, so a ready asset whose source was dropped answers
`asset_not_failed`.
