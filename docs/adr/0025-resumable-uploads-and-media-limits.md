# 0025. Resumable uploads and media limits

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M3-1, M3-2, M3-3)
- Deciders: project owner

## Context

D6 requires both S3 multipart uploads with presigned parts and tus, both resumable and both ending in
the same commit step. tus must not carry media through the control-plane API (I9). The plan also
needs default limits on what an upload may be.

## Options considered

- Where tus runs: the edge role; a new `upload` role; a tusd sidecar container.
- How D6's multipart path reconciles with I4 (presigned URLs contain the object key): exempt
  write-only part URLs; proxy parts through edge; presigned parts for servers only.
- How tus is implemented: tusd as a Go library; an own minimal tus server.
- Default limits: 10 GiB / 4 h; 5 GiB / 2 h; 20 GiB / 8 h.

## Decision

- **tus runs in the edge role** (the browser-facing listener; ADR 0008 unchanged). Each request is
  authorized by a short-lived, single-asset **upload token** issued by `api` when the upload is
  created; API keys never reach browsers.
- **tusd as a library** (`github.com/tus/tusd/v2`, MIT) with its S3 store and a Postgres- or
  storage-backed locker, wrapped with Cipherframe's authorization, object-key layout
  (`internal/storage/keys`), limits and error model. Chunks stream into an S3 multipart upload with
  bounded memory.
- **Multipart, proxied through edge**: `api` creates an S3 multipart upload; the client sends each
  part to edge (`PUT` with the upload token), and edge streams it into the matching S3 `UploadPart`
  with bounded memory. No presigned storage URL is ever returned, so **no response anywhere contains a
  source object key** (I4, M3-9) — every presigned S3 URL carries its object key in the path, which
  would otherwise contradict that test. This replaces D6's "presigned parts" wording: the multipart
  path stays resumable part by part, but its bytes flow through edge exactly as tus does.
- Both paths end in the same `commit` call on `api`, which verifies the object exists and its size,
  then enqueues processing in the same transaction.
- **Default limits** (configurable): source size **10 GiB**, duration **4 hours**, resolution up to
  **3840x2160**. Size is enforced at upload creation and again at commit; duration and resolution
  are enforced by the probe step (M3-3) before any encoding.

## Consequences

- All upload bytes pass through edge (both paths), so upload bandwidth and CPU scale with edge
  replicas; this is the price of never exposing a source key. Upload and playback share the edge
  listener; a dedicated role remains possible later. A
  dedicated role remains possible later without changing the API.
- One new dependency (tusd and its transitive modules), subject to the licence allowlist.
- Abandoned uploads leave incomplete multipart uploads and objects; they are cleaned up by expiry and
  found by the storage-enumerating purge (pitfall 8).
