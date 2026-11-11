# 0026. Asset and upload API

- Status: Accepted (flagged for owner review before v1.0.0)
- Date: 2026-11-11
- Gate: none (M3-1, M3-2, M3-9)
- Deciders: implementer, flagged for owner review before v1.0.0

## Context

ADR 0025 fixes the upload design: tus runs in the edge role through the tusd library, multipart parts
are proxied through edge, both end in one commit call on `api`, and no response may contain a source
object key. It does not name endpoints, token rules, state transitions or the shape of the answers.
M3-1 (asset lifecycle and API), M3-2 (resumable uploads) and M3-9 (source never addressable) had to
turn it into code. The names and rules below were not given by an owner decision, so they are
recorded here and flagged for review before the API is frozen at v1.0.0, as ADR 0018 does.

## Options considered

1. **Who authenticates an upload**: the API key (never exposed to browsers), a short-lived upload
   token bound to one asset, or a presigned storage URL (ruled out by ADR 0025).
2. **Where the tus resource lives**: addressed by the object key, by tusd's own `object+uploadID`,
   or by the asset ID.
3. **Where tusd keeps its objects**: tusd's default random IDs under a fixed prefix, or the asset's
   source key chosen in the pre-create hook.
4. **Commit semantics**: strict (409 if already committed) or idempotent.
5. **Cross-replica locking for tusd**: tusd's in-memory locker (one replica only), a file locker, or a
   Postgres advisory lock.

## Decision

**Lifecycle.** `created -> uploading -> committed -> processing -> ready | failed`, and `deleted`
from any state (its operation arrives later). Every change is a compare-and-set
(`UPDATE ... WHERE state = $expected`), and the allowed edges live in one Go table
(`internal/db/assetfsm.go`) whose test checks all 49 ordered pairs. A lost race is a `409 conflict`.
No separate transitions table: `audit_events` already records create, commit and abort, and the
asset row holds the timestamps (`committed_at`, `processing_started_at`, `ready_at`, `failed_at`)
and a `failure_code`.

**Source key.** `t/<tenant>/a/<asset>/source/<32 hex characters>`, from 128 random bits, stored on
the asset row (`keys.NewSource`). It cannot be derived from IDs, lies under `keys.AssetPrefixes`, and
is never returned, logged or placed in a job. No original file name is stored anywhere (privacy gate
P11 is pending); tus `Upload-Metadata` is dropped, and only the asset's own `content_type` is kept as
object metadata.

**Endpoints.**

| Operation | Listener | Authentication |
|---|---|---|
| `POST /v1/assets` | api | `assets:write` |
| `GET /v1/assets`, `GET /v1/assets/{asset_id}` | api | `assets:read` |
| `POST /v1/assets/{asset_id}/commit` | api | `assets:write` |
| `POST /v1/assets/{asset_id}/abort` | api | `assets:write` |
| `PUT /v1/uploads/multipart/{asset_id}/parts/{part_number}` | edge | upload token |
| `GET /v1/uploads/multipart/{asset_id}/parts` | edge | upload token |
| tus: `POST /v1/uploads/tus/`, `HEAD` and `PATCH /v1/uploads/tus/{asset_id}` | edge (tusd mount) | upload token |

- `POST /v1/assets` takes `{size_bytes, content_type?, upload_method}` (`tus` or `multipart`) and
  returns `{asset, upload}`. `upload` holds the method, the edge URL to use (the tus creation
  endpoint, or the multipart parts base URL), the **upload token**, its expiry and, for multipart,
  `part_size_bytes`. The response is `Cache-Control: no-store`: the token is shown only there.
- Lists use the keyset pagination of ADR 0018 (`limit`, `cursor`, `next_cursor`). Another tenant's
  asset, and a deleted one, is `not_found`.
- `size_bytes` is checked against `CIPHERFRAME_MAX_SOURCE_BYTES` (default 10 GiB) at create and again
  at commit; over the limit is `413 payload_too_large`. `content_type`, when given, must be a
  lower-case media type without parameters.
- The tus operations are documented in the spec under a `tus` tag and are **not generated**: tusd
  serves them. The contract test lists the mount as the one route-coverage exception and checks every
  documented tus operation against a real tus flow.

**Upload token.** `cfu_` plus 43 base64url characters (256 random bits). One per asset, bound to it,
stored as SHA-256 only (a fast hash is enough for 256 random bits), valid for
`CIPHERFRAME_UPLOAD_TOKEN_TTL` (default 24 h, 1 minute to 7 days). Edge looks it up in the database on
every request: an unknown, malformed or expired token, and a token whose asset is committed, failed or
deleted, are all the same `401 unauthenticated` with `WWW-Authenticate: Bearer`. A token used on
another asset's URL is `404`. API keys are never accepted on upload endpoints, and upload tokens are
never accepted on the API. Commit and abort delete the token. There is no endpoint to re-issue or
refresh a token; create a new asset.

**Commit.** From `uploading` only (`created` is `409`: nothing was uploaded; an asset already
`committed`, `processing` or `ready` returns itself and enqueues nothing). A multipart commit
validates the recorded parts (contiguous, at most the part size, all but the last at least 5 MiB, sum
equal to the declared size) and completes the S3 multipart upload; a tus commit requires the object to
exist, which tusd creates when the last chunk arrives. Both then `Head` the object and require exactly
the declared size. In one transaction the asset moves `uploading -> committed`, the token and part
records are deleted, an audit row is written and `asset.process` is enqueued with
`{tenant_id, asset_id}` as its only arguments. Concurrent commits enqueue exactly one job. If the
transaction fails after the multipart completion, a retry finds the object already assembled and
carries on.

**Abort.** From `created` or `uploading`: the asset becomes `failed` with `failure_code`
`upload_aborted`, the token and parts are deleted, an open multipart upload is aborted and every object
under the asset's source prefix is deleted (tus data, `.info` and `.part` included). Repeating it
repeats the cleanup, so a failed cleanup can be retried. A committed asset is `409`.

**Multipart parts.** `PUT` streams the request body into S3 `UploadPart` (`Content-Length` required,
at most the part size, together with the other parts at most the declared size) and records
`(part_number, etag, size)`; sending a part again replaces it. `GET .../parts` lists what was
received so a client resumes with the missing parts. The first part moves the asset `created ->
uploading`. Parts are at most `CIPHERFRAME_UPLOAD_PART_BYTES` (default 64 MiB, 5 MiB to 5 GiB; the
maximum source size divided by it may not exceed 10000).

**tus.** One tusd handler per edge process, with tusd's S3 store on the internal S3 client.

- *Object placement.* tusd builds every key from its upload ID. The pre-create hook sets that ID to
  the asset's source key and the S3 store's object prefix is empty, so the upload object, its `.info`
  object and its `.part` object are all `<source key>`, `<source key>.info` and `<source key>.part`:
  under `AssetPrefixes` by construction, and a test lists the bucket to prove it.
- *Facade.* Clients see the asset ID as the tus resource ID (`Location`, the URL of `HEAD` and
  `PATCH`). A wrapper around the S3 store translates it to the key plus the S3 multipart ID, which
  is kept on the asset row, and scrubs the key, the S3 ID, `Storage` and all metadata from what tusd
  can return. It also replaces every object-store error with a fixed text, because tusd copies
  `err.Error()` into response bodies and logs.
- *One upload per asset.* Creation runs under a row lock and a compare-and-set
  (`created -> uploading`, once, with the S3 multipart ID); a second creation is `409`. `Upload-Length`
  must equal `size_bytes`; deferred length is refused.
- *Disabled.* Termination (abort goes through the API), concatenation, deferred length and download
  (the source is never read back through edge).
- *Locking.* tusd needs one writer per upload. The locker takes tusd's in-memory lock (keeping its
  handshake that makes a reconnecting client take over from a dead request) and then a Postgres
  session-level advisory lock keyed by the asset ID, held on a dedicated connection pool of 64
  connections, so replicas exclude one another. Across replicas the second request polls until the
  holder finishes or tusd's lock timeout (20 s) passes.
- *Buffering.* tusd parks incoming data on local disk until a part is complete; edge allows two
  buffered parts and four concurrent part uploads per process, so one active upload may use about
  three part sizes of temporary disk.

**Edge CORS.** The multipart endpoints answer any origin (`*`, no credentials) because they are
authenticated by the token in the `Authorization` header, never by cookies; tus uses tusd's defaults.
Both flagged below.

**Configuration** (ADR 0013): `CIPHERFRAME_EDGE_PUBLIC_URL` (required when the api role runs),
`CIPHERFRAME_MAX_SOURCE_BYTES`, `CIPHERFRAME_UPLOAD_TOKEN_TTL`, `CIPHERFRAME_UPLOAD_PART_BYTES`.

**Dependency.** `github.com/tus/tusd/v2` v2.10.1 (MIT), with `golang.org/x/exp` (BSD-3-Clause, tusd's
logger type), `github.com/prometheus/client_golang`, `client_model`, `common` and `procfs`
(Apache-2.0), `github.com/beorn7/perks` (MIT) and `github.com/munnerz/goautoneg` (BSD-3-Clause). All
pass the licence allowlist. Only tusd's `handler`, `s3store` and `memorylocker` packages are linked.

## Consequences

- The source is not addressable by any response, header or log line (invariant I4, M3-9); the price is
  that all upload bytes pass through edge, as ADR 0025 states.
- An upload token holder can upload to that one asset until the token expires, is committed or is
  aborted. Tokens are not bound to a client address or origin.
- Uploads are not scanned for malware. Size and duration limits are DoS mitigations, not guarantees:
  edge still spends bandwidth, CPU and disk on whatever a token holder sends up to the limits.
- Choices not settled by the owner, chosen conservatively and open to change: the endpoint names and
  response shapes; idempotent (not strict) commit; `413` for an oversized declaration; the wildcard
  CORS origin on the multipart endpoints; no token re-issue endpoint; the 24 h token default; the
  variable names above; the lock pool size; `deleted` having no operation yet; no transitions
  history table.
- An abort racing a tus `PATCH` in flight can leave a `.part` object or a part after the cleanup; the
  storage-enumerating purge (pitfall 8) is the backstop. Abandoned uploads that nobody aborts leave
  incomplete multipart uploads until that purge or a bucket lifecycle rule removes them.
- Cross-replica tus takeover is polled, not signalled: a client reconnecting to another replica may
  wait up to the lock timeout.
- The multipart endpoints and tus both count on the S3 store giving strong read-after-write
  consistency, as SeaweedFS, S3 and R2 do.
- Renaming an operation path, a scope or a response field after v1.0.0 is breaking.
