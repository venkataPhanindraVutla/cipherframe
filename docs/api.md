# API

> Status: health and readiness (M1-6); authentication, clients and API keys (M1-7); assets, playback, integrity manifests, proofs and verify (M5-3).

## Source of truth

`spec/openapi.yaml` (OpenAPI 3.1) is the source of truth. Server interfaces and models are generated
from it with oapi-codegen (ADR 0004), and a contract test fails CI if the running API and the spec
diverge.

### How the spec drives the code

Every operation carries a tag naming the listener that serves it: `api` (control plane) or `edge`
(data plane). An operation served by both lists both tags. oapi-codegen runs once per listener and
generates a strict server interface from the operations with that tag:

| Listener | Generated code | Handlers |
|---|---|---|
| `api` | `internal/api/gen` | `internal/api` |
| `edge` | `internal/edge/gen` | `internal/edge` |

Regenerate after editing the spec, and commit the result:

```sh
go generate ./internal/api/gen ./internal/edge/gen
```

The generator is pinned in the `go:generate` lines (oapi-codegen v2.8.2) and runs through
`go run`, so nothing needs installing. CI regenerates and fails on any difference.

Adding an endpoint: describe it in the spec with its tags, regenerate, implement the new method the
compiler asks for, and run `go test ./internal/contract`. The contract test fails until the spec and
the registered routes agree.

### Contract test (ADR 0015)

`internal/contract` builds the real handler chain of both listeners, sends real HTTP requests to
them and validates every request and response against the spec with kin-openapi, including headers
and error responses (unknown path, wrong method, failing readiness). It also asserts that:

- the operations the spec assigns to a listener are exactly the routes registered on it, and every
  operation names at least one listener;
- the `Problem.code` enum in the spec equals `errs.Codes()`.

Requests the spec does not describe (404 and 405) must still return a valid `Problem`.

## Surfaces

| Surface | Callers | Authentication |
|---|---|---|
| Control plane | Embedding application servers | API keys; JWT and signed callback (M4-8, ADR 0029) |
| Data plane | Browsers | Short-lived playback tokens (ADR 0028) |
| Well-known keys | Anyone | None (public keys only) |

Each surface is its own listener (`CIPHERFRAME_API_LISTEN`, default `:8080`, and
`CIPHERFRAME_EDGE_LISTEN`, default `:8081`), started by the matching `--role` of
`cipherframe-server` (see [usage.md](usage.md)). Today each serves only the operations below.

| Operation | `api` | `edge` | Authentication |
|---|---|---|---|
| `GET /healthz` | yes | yes | none |
| `GET /readyz` | yes | yes | none |
| `GET /v1/whoami` | yes | no | any valid API key |
| `POST /v1/clients`, `GET /v1/clients` | yes | no | `admin` |
| `POST /v1/keys`, `GET /v1/keys` | yes | no | `admin` |
| `POST /v1/keys/{key_id}/rotate` | yes | no | `admin`, or the key itself |
| `POST /v1/keys/{key_id}/revoke` | yes | no | `admin` |
| `POST /v1/assets` | yes | no | `assets:write` |
| `GET /v1/assets`, `GET /v1/assets/{asset_id}`, `GET /v1/assets/{asset_id}/deletion-record` | yes | no | `assets:read` |
| `POST /v1/assets/{asset_id}/commit`, `POST /v1/assets/{asset_id}/abort`, `POST /v1/assets/{asset_id}/rekey`, `PATCH /v1/assets/{asset_id}`, `DELETE /v1/assets/{asset_id}` | yes | no | `assets:write` |
| `GET /v1/assets/{asset_id}/subtitles`, `GET /v1/assets/{asset_id}/subtitles/{subtitle_id}` | yes | no | `assets:read` |
| `POST /v1/assets/{asset_id}/subtitles`, `POST /v1/assets/{asset_id}/transcripts`, `DELETE /v1/assets/{asset_id}/subtitles/{subtitle_id}` | yes | no | `assets:write` |
| `GET /v1/brand/logo`, `PUT /v1/brand/logo`, `PATCH /v1/brand/logo`, `DELETE /v1/brand/logo` | yes | no | `admin` |
| `POST /v1/playback-sessions` | yes | no | `sessions:write` |
| `GET /v1/playback-sessions/{session_id}` | yes | no | `sessions:write` |
| `POST /v1/playback-sessions/{session_id}/revoke`, `POST /v1/playback-sessions/revoke` | yes | no | `sessions:write` |
| `GET /v1/playback-settings`, `PUT /v1/playback-settings` | yes | no | `admin` |
| `GET /v1/privacy-settings`, `PUT /v1/privacy-settings` | yes | no | `admin` |
| `GET /v1/assets/{asset_id}/access-log`, `GET /v1/playback-sessions/{session_id}/access-log` | yes | no | `assets:read` |
| `GET /v1/play/{session_id}/master.m3u8`, `GET /v1/play/{session_id}/{rendition}/media.m3u8` | no | yes | playback token (`manifest`) |
| `GET /v1/play/{session_id}/subtitles/{subtitle_id}/media.m3u8`, `.../track.vtt` | no | yes | playback token (`manifest`) |
| `GET /v1/play/{session_id}/poster.jpg`, `.../sprite.jpg`, `.../thumbnails.vtt` | no | yes | playback token (`manifest`) |
| `GET /v1/play/{session_id}/{rendition}/{file}` | no | yes | playback token (`segment`) |
| `GET /v1/play/{session_id}/key` | no | yes | playback token (`key`) |
| `POST /v1/play/{session_id}/heartbeat`, `POST /v1/play/{session_id}/end` | no | yes | playback token (`manifest`) |
| `PUT /v1/uploads/multipart/{asset_id}/parts/{part_number}` | no | yes | upload token |
| `GET /v1/uploads/multipart/{asset_id}/parts` | no | yes | upload token |
| tus: `POST /v1/uploads/tus/`, `HEAD` and `PATCH /v1/uploads/tus/{asset_id}` | no | yes (tusd mount) | upload token |

### Health and readiness

- **`GET /healthz`** (liveness) answers `200 {"status":"ok"}` whenever the process can serve a
  request. It checks no dependency, so a database outage never makes an orchestrator restart the
  process.
- **`GET /readyz`** (readiness) runs the dependency checks and answers `200` when all pass or `503`
  when any fails:

  ```json
  {"status":"unavailable","checks":[{"name":"database","status":"ok"},{"name":"storage_source","status":"unavailable"}]}
  ```

  The checks are `database` (a ping of the connection pool), `storage_source` and
  `storage_delivery` (a `HEAD` for a fixed object key under a reserved prefix: "not found" counts as
  reachable, a refused credential, a timeout or any other failure does not), and `queue` (the job
  queue's tables answer, so an unmigrated database is not ready). Each check has a
  2 second timeout, and checks run concurrently, so a hung dependency makes `/readyz` fail rather
  than hang. Use readiness, not liveness, to take an instance out of rotation.

Both endpoints are **public by design**: orchestrators and load balancers call them without
credentials. `/readyz` therefore reveals only the fixed check names and whether each passed. It
never includes host names, ports, error text or credentials; failure causes are not logged either,
only the check name and whether it timed out.

## Authentication and scopes (ADR 0009, 0018)

Control-plane requests carry an API key:

```
Authorization: Bearer cf_<prefix>_<secret>
```

The scheme name is case-insensitive. A key is `cf_`, a 12-character prefix (lowercase Crockford
base32), `_`, and a 43-character base64url secret (32 random bytes). The prefix is public: it
identifies the key in listings and logs. The secret is shown once, in the response that creates or
rotates the key (with `Cache-Control: no-store`), and is never stored: the database holds only
`HMAC-SHA256(pepper, secret)` and the pepper version (ADR 0016).

A missing, malformed, unknown, revoked or expired key, a wrong secret and a disabled client or
tenant all get the same answer: `401 unauthenticated` with a generic detail and
`WWW-Authenticate: Bearer`. A valid key without the needed scope gets `403 forbidden`. Health
endpoints need no key.

| Scope | Allows |
|---|---|
| `assets:read` | Read assets, status, deletion records, the access trail |
| `assets:write` | Create, upload, process and delete assets |
| `sessions:write` | Create and revoke playback sessions |
| `webhooks:manage` | Configure webhooks and replay deliveries |
| `admin` | Manage clients and keys for the tenant |

Each operation lists its scopes in `spec/openapi.yaml` (`security`); the server enforces them from a
table that a test compares with the spec.

### Clients and keys

Tenant > client > keys. Everything is scoped to the caller's tenant: another tenant's client or key
is `404 not_found`.

- `GET /v1/whoami` returns `tenant_id`, `client_id`, `key_id` and `scopes` of the calling key.
- `POST /v1/clients` with `{"name": "..."}` creates a client. `GET /v1/clients` lists them.
- `POST /v1/keys` with `{"client_id": "cli_...", "name": "...", "scopes": [...]}` creates a key.
  `scopes` defaults to every scope except `admin`; it must not be empty or contain duplicates.
  The response is the key metadata plus `key`, the full secret, **once**.
- `GET /v1/keys` lists the tenant's keys (revoked ones included) with metadata only: id, client,
  name, prefix, scopes, `created_at`, `rotated_at`, `previous_valid_until`, `revoked_at` and
  `last_used_at`. Never a secret or a hash.
- `POST /v1/keys/{key_id}/revoke` disables a key at once, including any still-valid previous
  secret. It is idempotent.

Names are 1 to 100 characters without control characters. Lists take `limit` (1 to 100, default
50) and `cursor`, and return `next_cursor` while more items follow; treat the cursor as opaque.
Every create, rotate and revoke writes an audit row with the action, the target ID, the request ID
and the acting client and key.

`last_used_at` is updated at most once a minute per key, so it can be up to a minute stale.

### Rotation with overlap

`POST /v1/keys/{key_id}/rotate` with an optional `{"overlap_seconds": N}` (0 to 86400, default 600)
replaces the key's secret **in place**: same key ID, prefix, client and scopes, so assets, sessions
and audit rows keep the same owner. The response carries the new full key once. The old secret
keeps working until `previous_valid_until`, so a deployment can roll the new key out without
downtime; with `overlap_seconds: 0` it stops at once.

A key with the `admin` scope may rotate any key of its tenant. Any other key may rotate **only
itself**; rotating another key is `403 forbidden`. Rotating a revoked key is `404 not_found`. A
second rotation inside the overlap replaces the previous secret again, so the secret before it
stops working.

### Bootstrap

The first admin key is created with the CLI, not the API:
`cipherframe-server admin bootstrap --tenant-name NAME --client-name NAME` (see
[usage.md](usage.md)). It prints only the key on stdout.

### What authentication does not protect against

- **A leaked key works until it is revoked**, or, after a rotation, until the overlap ends. Rotate
  on a schedule and revoke at once on suspicion. Nothing detects a stolen key being used from
  another place; `last_used_at` is a coarse hint.
- **Keys in client environments are the operator's responsibility**: environment variables, CI
  secrets, backups and logs of the embedding application. Cipherframe cannot see them.
- **HMAC with a pepper does not help against an attacker who holds both the database and the
  peppers.** Such an attacker still cannot read secrets back, but can test guesses offline. The
  secrets are 256 random bits, so guessing is not practical, but treat the pepper set as a secret
  of the same standing as the database credentials and back it up with them.
- A database without the peppers does not reveal usable keys. Losing the peppers invalidates every
  key (the server refuses to start while an active key references a missing version).
- There is no rate limiting or lockout on failed authentication yet; do not expose the api
  listener to the internet.
- A key's scopes cannot be changed after creation; revoke it and create another.
- There is no endpoint to disable a client or tenant. Authentication honours the database markers,
  but they can be set only with SQL for now.

## Assets and uploads (ADR 0025, 0026)

Endpoint names and shapes are flagged for owner review before v1.0.0.

An asset goes `created → uploading → committed → processing → ready | failed`, and from any of those to `deleting → deleted` when it is deleted (see "Delete").
The API never receives media: the embedding application creates the asset, hands the browser the
upload instructions, and commits when the upload is done. The source is never addressable: no
response, header or log line contains its object key or the source bucket's name, and no presigned
URL is ever returned.

**Create.** `POST /v1/assets` with `{"size_bytes": 1073741824, "content_type": "video/mp4",
"upload_method": "tus"}` (`tus` or `multipart`; `content_type` is optional). `size_bytes` must be
exact and at most `CIPHERFRAME_MAX_SOURCE_BYTES` (default 10 GiB; `413 payload_too_large`). No file
name is accepted or stored. `mask_faces` (boolean, default `false`) asks for a second, face-masked
variant of the asset (see "Variants" below); it is fixed at creation. `expires_at` or `ttl_seconds`
(not both) give the asset a time-to-live (see "Retention" below). The `201` answer,
`Cache-Control: no-store`:

```json
{
  "asset":  { "id": "ast_…", "state": "created", "size_bytes": 1073741824, "upload_method": "tus", "…": "…" },
  "upload": { "method": "tus", "url": "https://media.example.com/v1/uploads/tus/",
              "token": "cfu_…", "expires_at": "2026-11-12T10:00:00Z" }
}
```

For `multipart`, `upload.url` is `https://media.example.com/v1/uploads/multipart/<asset>/parts/` and
`upload.part_size_bytes` is the part size (default 64 MiB; the last part may be smaller).

**The upload token.** `upload.token` is 256 random bits, shown only in this response, valid for one
asset and for `CIPHERFRAME_UPLOAD_TOKEN_TTL` (default 24 h). Give it to the browser; send it to the
edge as `Authorization: Bearer cfu_…`. Edge checks it against the database on every request, so it
stops working at its expiry, when the asset is committed and when it is aborted. An expired,
unknown or ended token is `401 unauthenticated`; a token used on another asset's URL is `404`. API
keys are never accepted on upload endpoints, and upload tokens are never accepted on the API.

**Resumable upload with tus.** Speak tus 1.0.0 to `upload.url` with any tus client (for example
tus-js-client with `endpoint` set to it and an `Authorization` header). `Upload-Length` must equal
`size_bytes`. The upload URL is `…/v1/uploads/tus/<asset_id>`: after an interruption, `HEAD` it for
`Upload-Offset` and continue with `PATCH` from there. One upload per asset (a second creation is
`409`); client termination, concatenation and deferred length are disabled, and `Upload-Metadata` is
ignored. When the last byte arrives the object exists.

**Resumable upload with multipart.** Cut the file into `part_size_bytes` pieces and `PUT
<upload.url><n>` (`n` from 1) each with `Content-Length` and `Authorization: Bearer cfu_…`. Edge
streams the part into the object store and records it. After an interruption, `GET <upload.url>`
lists the parts received (`part_number`, `size_bytes`, `etag`) and the client sends only the missing
ones. Sending a part again replaces it. Every part but the last must be at least 5 MiB.

**Commit.** `POST /v1/assets/{asset_id}/commit` ends the upload: multipart is completed from the
recorded parts, then the object must exist with exactly the declared size (`409` if not; with tus the
upload must have finished). The asset becomes `committed`, the token stops working and processing is
queued, all in one transaction. Committing again returns the asset and queues nothing.

**Abort.** `POST /v1/assets/{asset_id}/abort` stops an uncommitted upload: the asset becomes `failed`
with `failure_code` `upload_aborted`, the token ends and the partial objects are deleted. Repeating it
repeats the cleanup; a committed asset is `409`.

**Read.** `GET /v1/assets/{asset_id}` and `GET /v1/assets` (`limit`, `cursor`, oldest first). An asset
of another tenant is `404`, never `403`. A deleted asset is still returned by `GET` as a tombstone
(`state: "deleted"`); lists leave deleted assets out.

**Retention (M6-4, ADR 0040, ADR 0042).** Assets are kept until deleted: with no time-to-live there is
no automatic deletion. A time-to-live makes the retention job (a worker role task that runs every five
minutes) start the verified deletion below with reason `retention` once `expires_at` has passed.
Set it at creation with `expires_at` (an absolute time) or `ttl_seconds` (seconds from now), each
between a minute and ten years from now (`400` otherwise, and `400` for both). With neither, the
tenant's default applies: `asset_ttl_seconds` in the privacy settings (an asset's expiry is fixed when
it is created, so changing the default does not touch existing assets). Change it later with
`PATCH /v1/assets/{asset_id}` (`assets:write`) and a body of exactly one member: `{"expires_at":
"2027-01-01T00:00:00Z"}`, `{"ttl_seconds": 86400}` (counted from now), or either set to `null` to clear
the expiry so the asset is kept until deleted. The asset shows `expires_at` while one is set. A
deleting asset takes no new expiry (`409`), a deleted one and another tenant's asset are `404`. The
sweep can be a few minutes late and an expired asset is deleted by the same purge as a requested one,
so it stays playable until the purge starts. Use `DELETE` to delete now.

**Keeping the original (H-3).** By default the uploaded original stays in the source bucket until the
asset is deleted. A tenant that keeps its own copy can set `keep_source` to `false` in the privacy
settings: an asset created from then on has its original deleted once it is `ready` (and, with
`mask_faces`, once its `masking.state` is `ready` or `failed`, since the masker reads the original).
The tus `.info` object and any multipart leftovers go with it. The value is fixed on the asset when it
is created, so changing the setting does not reach assets that already exist. The asset then shows
`source_deleted_at`, the audit log gets `asset.source_deleted`, and the original's bytes no longer
count toward the storage quota. Playback is not affected. A `failed` asset keeps its original, and
deleting an asset whose original is already gone works as usual.

**Delete (M6, ADR 0040, ADR 0042).** `DELETE /v1/assets/{asset_id}` (`assets:write`) starts the
verified deletion and answers `202` with the asset in state `deleting`. From that moment playback
(new sessions and key requests), uploads and processing refuse the asset and its active playback
sessions are revoked. The `asset.delete` job then deletes every object under the asset's prefixes in
both buckets (it lists storage, it does not trust the database alone), destroys the content keys of
every variant, lists storage again to confirm nothing is left (it retries on leftovers and fails
loudly rather than claim success), and leaves a signed deletion record (see
[integrity.md](integrity.md#verifiable-deletion)). Poll `GET /v1/assets/{asset_id}`: while the purge
runs `state` is `deleting` and `deletion` shows `reason` and `requested_at`; when it is done `state`
is `deleted` and `deletion.completed_at` is set. The row stays as a tombstone, and
`GET /v1/assets/{asset_id}/deletion-record` (`assets:read`) returns the signed deletion record as a
DSSE envelope (`Content-Type: application/vnd.cipherframe.deletion+json; profile=dsse`), also after
the asset is gone; before that it is `404 not_deleted`, and another tenant's asset is `404 not_found`.
Verify it with `cipherframe verify --deletion-record` ([integrity.md](integrity.md#the-deletion-record)). Deleting is idempotent: repeating the
call returns `202` again, and queues a new purge only if the earlier job is no longer in the queue
(this is how a deletion that ran out of retries is restarted). An in-flight processing or masking job
stops at its next check and removes its own output; it cannot bring the asset back.

**Re-key (M10-4, ADR 0068).** `POST /v1/assets/{asset_id}/rekey` (`assets:write`) queues an audited
re-encryption of a `ready` asset's segments under a new content key and answers `202` with the job
ID. The asset keeps playing under the old key until one transaction switches it; sessions that
started before the switch are refused the key (`401`) and must start a new session. Refused with
`409 asset_not_ready`, or `409 conflict` while the asset is being deleted, its masked variant is
still being made, or an earlier re-key is still queued or running. See [usage.md](usage.md#re-keying-an-asset).

**Variants (ADR 0036).** Every asset has an `original` variant. An asset created with `mask_faces:
true` also gets a `masked` variant, built after the original is `ready`. The asset shows
`"mask_faces": true` and `"masking": {"state": "pending" | "ready" | "failed", "faces_detected": 2}`
(`faces_detected` is absent until the masker has run; `0` means no face was found and the masked
variant was published anyway). An asset without `mask_faces` has `"mask_faces": false` and no
`masking`. Each variant has its own HLS tree and its own content key. This release stores and serves
variants and the `pending` state; building the masked variant is a later change, so `masking.state`
stays `pending` until then.

CORS: the multipart endpoints answer any origin without credentials, because the token in the
`Authorization` header is the only authentication; tus answers with tusd's defaults.

### What the asset and upload endpoints do not protect against

- A token holder can upload to that one asset until the token expires, is committed or is aborted.
  Tokens are not bound to an address, origin or device, and there is no endpoint to revoke one other
  than committing or aborting the asset.
- Uploads are not scanned for malware, and the bytes are untrusted until the worker probes them.
- The size limit and token lifetime bound what one token can send; they are DoS mitigations, not
  guarantees. Part sizes, buffering and concurrent uploads still cost edge bandwidth, CPU and disk.
- Duration and resolution limits are enforced later, by the probe step.
- An uploader can lie about `content_type`; it is stored as object metadata only.

## Subtitles and transcripts (ADR 0043, 0044)

Names and shapes are flagged for owner review before v1.0.0. An asset has up to 20 subtitle tracks.
A track is WebVTT, stored unencrypted in the delivery bucket, listed in the asset's signed manifest and
served only through a playback session.

| Operation | Route | Scope | Answers |
|---|---|---|---|
| `createAssetSubtitle` | `POST /v1/assets/{asset_id}/subtitles` | `assets:write` | `201` the track |
| `importAssetTranscript` | `POST /v1/assets/{asset_id}/transcripts` | `assets:write` | `201` the track |
| `listAssetSubtitles` | `GET /v1/assets/{asset_id}/subtitles` | `assets:read` | `200` `{"items": [...]}`, oldest first |
| `getAssetSubtitle` | `GET /v1/assets/{asset_id}/subtitles/{subtitle_id}` | `assets:read` | `200` the track |
| `deleteAssetSubtitle` | `DELETE /v1/assets/{asset_id}/subtitles/{subtitle_id}` | `assets:write` | `204` |

**Upload.** `multipart/form-data` with `file` (WebVTT or SRT, at most 2 MB; the format is read from the
content), `language` (a BCP 47 tag such as `en` or `pt-BR`, stored in canonical case), `label` (1 to 100
characters) and optionally `default` (`true` or `false`). The file name the client sends is ignored and
never stored. The track is rewritten from the parsed cues, so what is stored is always canonical WebVTT:

```sh
curl -X POST "$API/v1/assets/$ASSET/subtitles" -H "Authorization: Bearer $KEY" \
  -F file=@captions.srt -F language=en -F label=English -F default=true
```

```json
{
  "id": "sub_06gxtkpm49t09dtdnztknyq1wg", "asset_id": "ast_...", "language": "en", "label": "English",
  "default": true, "origin": "upload", "cue_count": 412, "size_bytes": 18302,
  "sha256": "9f...", "created_at": "2026-11-15T09:12:24Z"
}
```

**Import.** `POST /v1/assets/{asset_id}/transcripts` with JSON `language`, `label`, optional `default`, and
`cues`, a list of `start` and `end` (seconds from the start of the video, decimals allowed, rounded to the
millisecond), `text` (plain text, never read as markup) and optional `speaker` (written as a `<v>` tag).
The result is a track with `origin` `import`.

**Rules** (both routes, each breach is `400 invalid_request` with a field error that names the cue and
never quotes the content):

- At most 2 MB (`413 payload_too_large` above that; the request body may be up to 4 MB), UTF-8, no NUL; a
  byte order mark and CRLF line endings are accepted.
- Every cue has a time range in `[hh:]mm:ss.ttt` (SRT: `hh:mm:ss,ttt`), ends after it starts, does not
  start before the cue before it, and ends no later than the asset's duration plus 2 seconds. Cues may
  overlap. At most 20000 cues, 1000 characters and 12 lines per cue; a cue with no visible text is refused.
- Only plain text and the tags `b`, `i`, `u`, `v`, `lang` and `c` are kept. Every other tag, cue setting,
  identifier, note, style and region is dropped, and `&`, `<` and `>` are written as references.
- At most 20 tracks (`409 conflict` for the next) and at most one default: a new default replaces the old
  one, and deleting the default promotes none.
- Only a `ready` asset takes tracks: `409 asset_not_ready` otherwise, `409 conflict` while it is being
  deleted, `404 not_found` once deleted and for another tenant's asset or track.

Each add or delete signs the manifest again (see [integrity.md](integrity.md#subtitle-tracks)) and writes
an audit event (`asset.subtitle.add`, `asset.subtitle.delete`). Responses never carry a storage key.

**Serving.** The master playlist of a session lists the asset's tracks as an `EXT-X-MEDIA` group of type
`SUBTITLES` (`GROUP-ID="subs"`, one `NAME`, `LANGUAGE`, `DEFAULT` and `URI` each) and names the group on
every variant. A player follows `URI` (`subtitles/<id>/media.m3u8`), whose one segment is `track.vtt`; with
`token_in_url` on, both URIs carry `?t=<token>` like the others. Both routes check what the media playlists
check: a `manifest`-scope token, the session row (a revoked, ended or idle session gets the one `401`),
the tenant's CORS settings. The track is found by the tenant and asset in the token, so a session never
reads another asset's track (`404`). Responses are `no-store`.

### What the subtitle endpoints do not protect against

- Tracks are **not encrypted**. Access control is the session: anyone with a valid session can fetch and
  keep a track, and the content key plays no part. Do not upload subtitles that must stay secret.
- The label is not signed (it is not in the manifest); the words, language, default flag and origin are.
- A session that already fetched its master playlist keeps the track list it saw; a deleted track is `404`
  for it.
- Cue positioning and styles are dropped, and nothing translates or checks the words.

## Thumbnails (ADR 0046)

Every asset processed after M7-2 has, for each variant (the original and, with `mask_faces`, the
masked one), a poster, a sprite sheet and a WebVTT thumbnail track. There is no endpoint to list or
upload them: they are made by the worker in the same FFmpeg run as the renditions and are read only
through a playback session, on the same guard as the media playlists (a `manifest`-scope token, the
session row, `token_in_url`, CORS, the one generic `401`).

| Route | Returns |
|---|---|
| `GET /v1/play/{session_id}/poster.jpg` | A JPEG poster frame, taken at 10 percent of the video, at most 640 pixels wide. |
| `GET /v1/play/{session_id}/sprite.jpg` | A JPEG sheet of thumbnail tiles (each at most 160 x 288), at most 10 per row, one every 10 seconds (a longer interval for a very long video, at most 600 tiles). |
| `GET /v1/play/{session_id}/thumbnails.vtt` | The thumbnail track (`text/vtt`): one cue per tile, `sprite.jpg#xywh=x,y,w,h`. |

**How a player finds them.** The names are fixed and sit beside the master playlist: take `manifest_url`
and replace `master.m3u8` with `poster.jpg` or `thumbnails.vtt` (with `token_in_url` on, keep the
`?t=<token>`). The cues name the sprite as the relative `sprite.jpg`, which resolves to the session's own
sprite route, and carry the token when `token_in_url` is on. Pass the poster to the player's poster
option and the track to its thumbnail or preview support (for example a `metadata` text track). The
session creation response and the master playlist do not list them, and there is **no I-frame
playlist**: segments are encrypted whole, so a playlist of byte ranges into them could not be decrypted
(ADR 0046). An asset processed before thumbnails existed, or whose images were skipped, answers `404`.

- **A session sees only its own variant's images.** A session bound to the masked variant gets images made
  from the masked output, and `404` if there are none; it is never answered with an original's image.
- **Always through edge.** Thumbnails are unencrypted images of faces, so they are streamed by edge for
  every tenant, including those with `delivery: presigned`: no thumbnail URL is a storage URL, and
  nothing about them is public. Anyone with a valid session can keep them, as with subtitle tracks.
- Responses are `image/jpeg` or `text/vtt`, `no-store`, `Referrer-Policy: no-referrer`, with
  `Content-Length`. A fetch is not a row in the access trail.
- The three objects are in the signed manifest by hash (see [integrity.md](integrity.md#thumbnails)):
  `POST /v1/verify` with `asset_id`, `variant` and path `poster.jpg`, `sprite.jpg` or `thumbnails.vtt`
  answers `ours` or `modified` with no proof.

## Brand logo (ADR 0043, 0049)

A tenant can have one logo that is burned into the video of every asset transcoded afterwards. All four
operations need the `admin` scope and act on the caller's tenant.

| Method and path | What it does |
|---|---|
| `PUT /v1/brand/logo` | Uploads a logo as a new version and makes it current. `200` with the logo. |
| `GET /v1/brand/logo` | The current logo's metadata (never the image). `404 not_found` when there is none. |
| `PATCH /v1/brand/logo` | Changes `corner`, `opacity_percent` or `enabled` without a new upload (JSON, fields left out keep their value). `404` when there is none. |
| `DELETE /v1/brand/logo` | Removes the logo. `204`; `404` when there is none. |

`PUT` takes `multipart/form-data`: `file` (required), `corner` (`top_left`, `top_right`, `bottom_left`,
`bottom_right`; default `bottom_right`), `opacity` (a whole number of percent, 10 to 100; default 100) and
`enabled` (`true` or `false`; default `true`). The response and `GET` are `version` (the stored version's
ID), `sha256` and `size_bytes` (of the PNG the server stored), `width`, `height`, `corner`,
`opacity_percent`, `enabled`, `created_at` (of the version) and `updated_at`. Errors: `400 invalid_request`
with a field error on `file`, `corner`, `opacity` or `enabled` (never quoting the file), `413
payload_too_large`, `401`, `403`, `429`, `503`.

**What is accepted.** A still PNG of at most 256 KB, 16 to 1024 pixels on each side. The server checks
the size, then the PNG signature, then the header's dimensions (a tiny file that claims a huge image is
refused before it is decoded), then decodes the whole file. An animated PNG and a fully transparent
image are refused (`400`). It then writes the picture again with its own PNG encoder and stores only
that: text, EXIF, colour profiles and every other chunk of your file are dropped, and the `sha256` is
the hash of the re-encoded file. The file name you send is ignored and never stored or logged.

**Where it is drawn.** At 15 percent of each picture's width (never taller than a quarter of its
height, so a very tall logo shrinks), 2 percent of the width in from the chosen corner, blended at the
opacity, on every rendition and also on the poster and the sprite tiles (ADR 0049). The masked variant
gets the same logo, drawn after the faces are blurred.

**Not retroactive.** The logo is part of the encoded video. A new upload, a changed placement and a
removal affect only assets whose processing starts afterwards:

- An asset that is being processed keeps the logo it started with, also when the job is retried and for
  its masked variant, even if you change the logo meanwhile.
- An asset that is already `ready` keeps its video as it is. Cipherframe has no re-transcode, so a new
  logo does not appear on your existing videos and **removing the logo does not remove it from videos
  already made**. To rebrand an old video, upload its source again as a new asset.
- Each asset's signed manifest says which logo it was made with (`encoder.logo`, and `masked.logo`; see
  [integrity.md](integrity.md#the-brand-logo)).
- Old stored versions are deleted when a change leaves no asset that is still being processed (or whose
  masked variant is still to be made) depending on them, at the next upload or removal.

Every change is audited (`brand.logo.put`, `brand.logo.update`, `brand.logo.delete`) with the version
ID and no file name.

### What the brand logo does not protect against

- **Removal by someone who has the file.** The logo is deterrence and branding, not a watermark of a
  viewer: it is identical for every viewer and anyone can crop or paint over a recording.
- **A tenant's own mistake.** A wrong logo burned into a video stays there; see "Not retroactive".

## Playback sessions and settings (ADR 0028, 0030)

Endpoint names and shapes are flagged for owner review before v1.0.0. This section covers the
control plane, the edge playlist, segment and key routes, and the session lifecycle: heartbeat, end
and revoke (below).

**Start a session.** `POST /v1/playback-sessions` (scope `sessions:write`) with
`{"asset_id": "ast_…", "viewer_id": "u-8f3a…"}`, and optionally `"variant": "original" | "masked"`.
The asset must belong to your tenant and be `ready`. The `201` answer, `Cache-Control: no-store`:

```json
{
  "session_id": "ses_…",
  "token": "v1.…",
  "token_expires_at": "2026-11-12T10:10:00Z",
  "heartbeat_interval_seconds": 60,
  "session_expires_at": "2026-11-12T14:00:00Z",
  "manifest_url": "https://media.example.com/v1/play/ses_…/master.m3u8",
  "token_transport": "header",
  "variant": "original"
}
```

When the tenant turned the [overlay watermark](#overlay-watermark-adr-0043-0048) on, the answer also holds an
`overlay` object (every creation path: this one, and the browser JWT and callback paths below). It is absent
while the overlay is off.

**The session's variant.** A session is bound to one variant for its whole life, and edge serves only
that variant's playlists, segments and key: a `masked` session cannot fetch a byte or the key of the
`original`, and the reverse. Without `variant`, an asset created with `mask_faces` gets `masked` and
any other asset gets `original`; to play the original of a masking asset you must ask for
`"variant": "original"` explicitly, which is your application's decision. There is never a fallback.

Give `manifest_url`, the token and the heartbeat interval to the player. With `token_transport`
`header` (the default) the player sends `Authorization: Bearer <token>` on every request to edge, and
no URL contains the token. The token allows the manifest, key and segment requests of this one
session and asset, and expires after the tenant's token TTL (10 minutes by default), never later than
the session itself. The session ends after 4 hours at most, or after 5 minutes without a heartbeat.

| Status | Code | When |
|---|---|---|
| `400` | `invalid_request` | `viewer_id` or `asset_id` is malformed (see `errors`). |
| `403` | `forbidden` | The key lacks `sessions:write`. |
| `404` | `not_found` | No such asset, including an asset of another tenant (never `403`). |
| `409` | `asset_not_ready` | The asset is not `ready` (still uploading or processing, or failed). |
| `409` | `variant_unavailable` | `variant` is `masked` but the asset was created without `mask_faces`. |
| `409` | `variant_not_ready` | The masked variant is requested (or is the default) and is not `ready` (`pending` or `failed`). |
| `409` | `session_limit` | The viewer already has the maximum number of active sessions. |
| `409` | `quota_exceeded` | The tenant or the client is at its `concurrent_sessions` quota ([Quotas and usage](#quotas-and-usage-adr-0047)). |

**Viewer IDs and privacy.** `viewer_id` (1 to 128 printable characters, no control characters) is
stored with the session and is the key of the concurrency limit. Use a **pseudonymous** identifier
that only your application can link to a person, for example a random user ID or a keyed hash. Never
send an email address, a name, a phone number or another direct identifier: Cipherframe has no use
for one, and it would then sit in session rows. It is not returned in any response, written to any
log or sent to the browser.

**Concurrency limit.** By default a viewer (your `viewer_id`, within your tenant) may have 3 active
sessions. A fourth is `409 session_limit` and the existing sessions are left alone (they are not
revoked to make room). A session counts as active until it is revoked or ended, until it has had no
heartbeat for the idle timeout, or until it reaches its maximum age; idle and expired ones are marked
`ended` the next time that viewer starts a session, and by a background sweep (see "Cleanup" below).
A player that ends its session on close (below) frees its slot at once. The check and the insert run under a lock on the
(tenant, viewer) pair, so parallel requests cannot exceed the limit. `max_sessions_per_viewer` `0`
means unlimited.

**Where the secrets live.** A session ID and a token grant playback, so the database stores only the
SHA-256 of the session ID, and neither appears in a log line or an error. The token is shown only in
this response (the manifest URL carries it only when the tenant turned `token_in_url` on). Anyone who
holds a token can play until it expires: tokens are not bound to an address or a device, and revoking
a session stops playlists, key fetches and heartbeats at once but not the segments already covered by a
token (AES-128 HLS is not DRM, ADR 0028).

**Settings.** `GET /v1/playback-settings` (scope `admin`) returns the tenant's effective settings;
`PUT /v1/playback-settings` replaces all of them (send every field). A tenant that never set any uses
the defaults, and `updated_at` is absent until the first `PUT`.

| Field | Default | Range | Meaning |
|---|---|---|---|
| `token_ttl_seconds` | 600 | 60 to 3600 | How long a token works. |
| `heartbeat_interval_seconds` | 60 | 10 to 600 | How often the player sends a heartbeat. Less than the token TTL and the idle timeout. |
| `idle_timeout_seconds` | 300 | 30 to 3600 | A session without a heartbeat for this long ends. |
| `session_max_seconds` | 14400 | 300 to 86400 | Maximum session age. |
| `max_sessions_per_viewer` | 3 | 0 to 100 | Active sessions per viewer; 0 is unlimited. |
| `key_fetches_per_token` | 20 | 1 to 1000 | Successful key responses one token may get (key endpoint, below). |
| `key_requests_per_minute` | 30 | 1 to 600 | Key requests one session may make per minute, rejected ones included (key endpoint, below). |
| `allowed_origins` | `[]` | at most 20 | Browser origins allowed to play (CORS on edge, see below). |
| `token_in_url` | `false` | | Put the token in the manifest URL for native HLS players. |
| `delivery` | `proxy` | `proxy`, `presigned`, `cdn` | How segments reach the player (see below). `cdn` needs a CDN configured on the deployment; without one the request is refused with a field error on `delivery`. |
| `anomaly_sessions_per_viewer_10m` | 10 | 0 to 1000 | More sessions than this created for one viewer in 10 minutes raises `rapid_session_creation`; 0 turns it off ([anomaly signals](#anomaly-signals-m4-9)). |
| `anomaly_segments_without_key` | 30 | 0 to 100000 | More segments than this served to a session that never fetched the key raises `segments_without_key`; 0 turns it off. `proxy` delivery only. |
| `auto_revoke` | `[]` | any of `key_replay`, `key_rate`, `rapid_session_creation`, `segments_without_key` | Kinds whose signal also revokes the session (the viewer's sessions for `rapid_session_creation`). Empty is off. |
| `extra_codecs` | `[]` | any of `hevc`, `av1` | Video codecs made beside H.264 for assets uploaded from now on (ADR 0064, [codecs.md](codecs.md)). Each adds a full ladder. Turning one on is refused with a field error on `extra_codecs[i]` when no worker seen in the last 5 minutes can encode it. An asset reports the setting it was created with as `extra_codecs.requested`, and the codecs it did not get, with a reason, as `extra_codecs.failed`. |

`allowed_origins` entries are exact origins as a browser writes them: `https://host[:port]`, or
`http://localhost[:port]` for development. Lower case, no path, no trailing slash, no wildcard, no
user information, and no port that is the scheme's default (`https://example.com`, not
`https://example.com:443`). Duplicates are rejected. An invalid request is `400 invalid_request` with
one `errors` entry per field, for example `allowed_origins[1]`, and nothing is stored. A change
applies to new sessions, and edge picks up `token_in_url`, `delivery`, `allowed_origins` and `idle_timeout_seconds`
within 30 seconds (its settings cache).

**Token in URLs (`token_in_url`).** Off by default, so no URL carries a token (pitfall 9). Turn it on
only for tenants that must support native HLS players (for example Safari on iOS) that cannot set
headers: `manifest_url` then ends in `?t=<token>` and `token_transport` is `url`. The token can then
appear in browser history and in the logs of proxies and CDNs that you do not control; it lasts at
most the token TTL, and revoking the session still stops key fetches. Edge strips the parameter from
what it logs and sends `Referrer-Policy: no-referrer` (ADR 0030).

**Delivery (`delivery`).** `proxy` (the default) serves every init and media segment through edge,
after the token check. With `presigned`, the media playlist the player gets carries, for the init
segment and for each media segment, a presigned GET URL for that object in the delivery bucket, so
storage or a CDN serves the bytes and edge does not (ADR 0032). The master playlist and the key URI
(`../key`) are unchanged, so the key endpoint still checks the session on every fetch and revocation
still applies. The edge segment route keeps working in every mode.

With `cdn` (ADR 0062), the URLs are instead signed URLs of the deployment's CDN (CloudFront or Cloud CDN),
with the same expiry rule and the same rest: playlists, keys and thumbnails stay on edge. A session
that is revoked can still fetch the segments it already has URLs for until they expire (at most 10
minutes); without the key, which the key endpoint refuses, they cannot be decrypted. After an asset
is deleted a purge removes it from the CDN's cache ([cdn.md](cdn.md)).

- A URL lives until the playback token expires or 10 minutes, whichever is first (at least 1 second;
  a token with under a second left gets `401`). The player gets fresh URLs each time it fetches the
  media playlist, so a player that reloads the playlist (or fetches it again after expiry) keeps
  playing; a client that holds one playlist for longer than the lifetime sees `403` from storage.
- Segments are ciphertext in both modes, so a presigned URL exposes only encrypted bytes, and only
  until it expires. It is still a credential: signed storage URLs appear in playlists, in browser
  history and in the logs of proxies and CDNs you do not control, as a token does with `token_in_url`.
  Edge never logs them.
- The URLs point at `CIPHERFRAME_S3_PUBLIC_ENDPOINT`, which must be reachable by the player, and
  the delivery bucket needs a CORS rule that allows your origins to GET (docs/usage.md). Source
  objects are never presigned, and neither are the poster, the sprite sheet and the thumbnail track: they
are unencrypted images, always served by edge (ADR 0046).

### Playlists and segments on edge (ADR 0027, 0030)

Six `GET` routes on the edge listener serve a session. The player starts at `manifest_url` and
follows the URIs in the playlists; it never builds a URL itself.

| Route | Scope | Returns |
|---|---|---|
| `/v1/play/{session_id}/master.m3u8` | `manifest` | The master playlist. Each variant URI is `<rendition>/media.m3u8`. |
| `/v1/play/{session_id}/{rendition}/media.m3u8` | `manifest` | One rendition's media playlist. |
| `/v1/play/{session_id}/{rendition}/{file}` | `segment` | `init.mp4` (`video/mp4`) or `seg-<n>.m4s` (`video/iso.segment`), streamed from the delivery bucket with `Content-Length`. |
| `/v1/play/{session_id}/key` | `key` | The 16-byte AES-128 content key, raw (`application/octet-stream`). See below. |
| `/v1/play/{session_id}/subtitles/{subtitle_id}/media.m3u8` | `manifest` | One subtitle track's media playlist (one WebVTT segment). See "Subtitles and transcripts". |
| `/v1/play/{session_id}/subtitles/{subtitle_id}/track.vtt` | `manifest` | The track's WebVTT file (`text/vtt`), unencrypted, `no-store`. |
| `/v1/play/{session_id}/poster.jpg`, `.../sprite.jpg`, `.../thumbnails.vtt` | `manifest` | The session variant's poster, sprite sheet and thumbnail track, unencrypted, `no-store`, always through edge. See "Thumbnails". |

**Rewriting.** The stored playlists are canonical templates with the placeholder `cipherframe-key`
as the key URI (ADR 0027). Edge rewrites them per request with a strict line rewriter that touches
only URI lines and `URI="..."` attributes and refuses a stored playlist that holds anything else.
In a media playlist the key URI becomes the relative `../key`, which resolves to
`/v1/play/{session_id}/key` (served as described below), and the init and
segment URIs are file names relative to the rendition. A relative URI works behind any path prefix
and carries nothing secret. Playlists are `Content-Type: application/vnd.apple.mpegurl`,
`Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Segments are
`Cache-Control: private, max-age=300` and `Referrer-Policy: no-referrer`.

**The token** (ADR 0030). Send `Authorization: Bearer <token>` on every request. Only when the tenant
has `token_in_url` on is the query parameter `t` accepted too, and then every URI in the playlists
carries `?t=<token>`. A request with both forms, or `t` twice, is `400 invalid_request`. With
`token_in_url` off, `t` is refused with `401`. Every other token failure (missing, malformed, bad
signature, expired, wrong scope, a token for another session than the one in the path) is the same
`401` with one generic detail and `WWW-Authenticate: Bearer`. The asset and tenant come from the
token, never from the request.

**What is checked where.** Segments are stateless: edge verifies the token (signature, expiry,
scope, session) and streams the object, with no database query on a cache hit. Playlists also read
the session row, so a session that is revoked, ended, past its maximum age, or without a heartbeat for
the idle timeout gets `401` (the same answer as a bad token, so the status does not say why).
The key endpoint reads the session row on every request, uncached, with the same rules as the
playlists. Consequence, by design: **a revoked session can still fetch segments until its token
expires** (10 minutes by default). They are unreadable without the key, and the key endpoint checks
the session on every fetch.

**Path values** are checked against an allowlist before anything else: the session ID, a rendition
(`[a-z0-9_]{1,16}`) and a file (`init.mp4` or `seg-<n>.m4s`, no leading zeros). A path under
`/v1/play/` that has a percent escape, a backslash, an empty segment, `.` or `..` is `404`, and none of
it reaches the object store. A rendition or segment that does not exist is `404`. A storage outage is
`503` (`504` on a timeout, `500` for refused storage credentials), never `404`.

**CORS.** Edge answers a browser origin that is, byte for byte, in the tenant's `allowed_origins`: it
sets `Access-Control-Allow-Origin` to that origin. Every playback response carries `Vary: Origin`. Any
other origin, and a request without an `Origin`, gets no CORS headers and the usual response, so the
browser blocks the read. The preflight `OPTIONS` on the playback routes needs no token and is always
`204`; for an allowed origin it adds `Access-Control-Allow-Methods: GET, POST, OPTIONS`,
`Access-Control-Allow-Headers: Authorization` and `Access-Control-Max-Age: 600`. Credentials are never
allowed. A `401` carries the CORS headers too, so a player can read it and refresh its token.

**Logging.** The access log records the route pattern, never the URL, so neither the token, the `t`
parameter nor the session ID is logged. Where a session must be named (an error line), edge logs a
short one-way fingerprint of it (the first 4 bytes of its SHA-256).

### The key endpoint (ADR 0027, 0028)

`GET /v1/play/{session_id}/key` returns the asset's content key: exactly 16 raw bytes with
`Content-Type: application/octet-stream`, `Cache-Control: no-store, private`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer` and `Content-Length: 16`. A media playlist's `EXT-X-KEY` tags point at it
as `../key`, so a standard HLS player fetches it by itself. It needs a token with the `key` scope
(tokens from `POST /v1/playback-sessions` carry all three scopes). The `t` parameter and CORS follow
the other playback routes; the preflight needs no token.

**Checks, in order.**

1. The token, the session in the path and the tenant's settings, as for every playback route.
2. The session row is read from the database on every request and never cached: it must be `active`,
   before its maximum age, with a heartbeat within the idle timeout, and for the token's asset. A
   revoked session gets `401` on its next key request even though its token still verifies.
3. The asset must still be `ready` and have a content key. An asset that was deleted, or whose key was
   destroyed, is the same `401`. (Every cause of `401` has one generic detail and
   `WWW-Authenticate: Bearer`.)
4. The bounds below, then the key service. If the key service or the database is unavailable the answer
   is `503 dependency_unavailable`, never `401` or `404` (I11).

**Bounds.** Both are kept in Postgres, so they hold across edge replicas and restarts.

| Bound | Setting | Counted |
|---|---|---|
| Per token | `key_fetches_per_token` (20) | Successful key responses only. A token is identified by the SHA-256 of its text; the token is never stored. |
| Per session | `key_requests_per_minute` (30) | Every key request that passes the session check, rejected ones included, in a fixed one-minute window that starts with the first request. |

Past either bound the answer is `429 rate_limited` with a `Retry-After` header (whole seconds, at
least 1):

- Per-session bound: `Retry-After` is the time left in the window (at most 60). The window restarts
  after it, so a player that backs off is served again.
- Per-token bound: the token will not get the key again, so `Retry-After` is the tenant's
  `heartbeat_interval_seconds`. A well-behaved player sends its heartbeat, receives a fresh token and
  tries again with it. A fresh token has its own fetches, subject to the session's per-minute window.

A request rejected for the per-token bound is not a successful key response, so it does not count
against that bound (and a `429` never carries the key). It does count in the per-minute window, so a
client that keeps hammering stays rejected. A request that fails because the key service or the
database is down does not use up one of the token's fetches either.

**Anomaly events.** The first time a token is over its bound, a `key_replay` signal is raised; the
first request past the per-minute bound in a window raises a `key_rate` signal. Later rejected
requests for the same token or window raise nothing. What a signal does is described under
[Anomaly signals](#anomaly-signals-m4-9).

**Cleanup.** The per-token counters live in `playback_key_fetches`, one row per token that asked for a
key. The edge role deletes the rows of tokens that expired more than five minutes ago, every ten
minutes (and once at start-up), so the table stays about as large as the tokens of the last
`token_ttl_seconds` plus a few minutes.

### Anomaly signals (M4-9)

Cipherframe raises a small set of **signals** for patterns that look like scraping or token sharing. A
signal is an **event** you can read (`GET /v1/playback-events`) and, if you ask for it, a
revocation. A signal is a hint and not a verdict: every one of them can be triggered by an unusual but
honest player, which is why revoking automatically is off by default.

| Kind | Raised when | Raised at most | `detail` |
|---|---|---|---|
| `key_replay` | One playback token asked for the key more than `key_fetches_per_token` times. | once per session per 10 minutes | `limit` |
| `key_rate` | One session asked for the key more than `key_requests_per_minute` times in a minute. | once per session per 10 minutes | `limit` |
| `session_limit` | A session creation was refused with `session_limit`. | once per viewer per 10 minutes | none |
| `rapid_session_creation` | More than `anomaly_sessions_per_viewer_10m` sessions were created for one viewer in a sliding 10 minutes. | once per viewer per 10 minutes | `limit`, `sessions` |
| `segments_without_key` | A session was served more than `anomaly_segments_without_key` segments without ever being served the key. | once per session | `limit`, `segments` |

- **Thresholds** are playback settings, per tenant: `anomaly_sessions_per_viewer_10m` (0 to 1000,
  default 10) and `anomaly_segments_without_key` (0 to 100000, default 30). `0` turns that signal off.
  The two key signals use the existing bounds, which cannot be switched off (`key_fetches_per_token`
  and `key_requests_per_minute`, minimum 1); `session_limit` follows `max_sessions_per_viewer`, where
  0 means unlimited and so never refuses. A normal viewer stays far from every default: a player
  fetches the key a handful of times a session, a person rarely starts more than a few sessions in ten
  minutes, and a player fetches the key before its first segment.
- **How they are counted.** The key and session-creation signals use the counters those endpoints
  already keep (the per-token and per-minute key counters, the session rows' `created_at`), so they
  are exact and shared by every replica. `segments_without_key` is counted on the session row: every
  edge replica adds its segment counts to the session at each segment-count flush (about every 30
  seconds, one batched statement per replica), and the key endpoint stamps the session the first time
  it serves the key. It does not read the access trail, which is best effort and could drop a `key` row
  and so accuse a viewer who did fetch the key. **It only works with `proxy` delivery:** with
  `presigned` delivery storage serves the segments, edge never counts them and the signal never
  fires. Detection runs about 30 seconds after the segments were served, not in the request.
- **Duplicates.** One event per subject (a session, or a viewer for the viewer-level kinds) and kind per
  10 minutes, so a scraper that keeps going does not fill the table; `segments_without_key` is once
  per session for the life of the session, because the condition never clears.
- **Auto-revoke** (`auto_revoke`, a list of kinds, default empty = off). When the signal of a listed
  kind is detected the session is revoked with the reason `auto:<kind>`, the access trail gets a
  `revoked` row, and an audit event `playback_session.auto_revoke` is written (no client or key: nobody
  asked for it). For `rapid_session_creation` every active session of the viewer is revoked, including
  the one that crossed the line. Allowed kinds: `key_replay`, `key_rate`, `rapid_session_creation`,
  `segments_without_key`. `session_limit` is not allowed: a refused creation has no session to revoke
  and a retrying player would lose its viewer. A revoked session's key endpoint answers `401` at once;
  segments follow the token, as for any revocation (below). The revocation is applied whenever the
  condition is detected, even when the event itself was suppressed as a duplicate, so a scraper that
  starts a new session after the first was revoked is revoked again. It is also done in the same
  database transaction as the event, so there is no revocation without its event.
- **Failures are never abuse (I11).** If the event cannot be stored, or the tenant's settings cannot be
  read, nothing is revoked, the failure is logged (kind and a session fingerprint, nothing else) and
  the viewer's request is answered as usual.

**Reading events.** `GET /v1/playback-events` (scope `assets:read`) returns `{items, next_cursor}`,
**newest first**. Filters: `kind`, `asset_id`, `viewer_id`, `from` (inclusive) and `to` (exclusive) as
RFC 3339 times, `limit` (1 to 500, default 100) and `cursor` (the opaque `next_cursor` of the previous
page). A bad filter is `400` with an `errors` entry; an asset ID of another tenant matches nothing. An
item is `{id, kind, at, asset_id, viewer_id, session, detail}`: `session` is the 8-hex-character
fingerprint the access trail shows, so the two can be matched; it is absent for viewer-level kinds, and
no response holds a session ID, a token or the hash of a session ID. `detail` holds small integers only
(the limit and the count). A tenant only ever sees its own events.

**Webhooks.** Every stored event is also sent to the tenant's webhook endpoints as a `session.anomaly`
event, with the same `id` as here (see [Webhooks](#webhooks-adr-0045)); this endpoint stays the way to
read them. Events are removed after the access-trail retention window
(`CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`, default 90 days).

### Heartbeat and end: the player contract (ADR 0028)

A session is kept alive by the player, which calls edge on a timer.

**Heartbeat.** Every `heartbeat_interval_seconds` (60 by default; it is in the session response and in
every heartbeat response) send `POST /v1/play/{session_id}/heartbeat` with the current token, an empty
body and the same `Authorization: Bearer` header (or `?t=` where the tenant allows it) as for the
playlists. The answer is `200`, `Cache-Control: no-store`:

```json
{
  "token": "v1.…",
  "token_expires_at": "2026-11-12T10:20:00Z",
  "heartbeat_interval_seconds": 60,
  "session_expires_at": "2026-11-12T14:00:00Z"
}
```

**Swap in the new token for every later request**: playlists, key and segments alike. It carries all
three scopes and expires one token lifetime from now, never later than `session_expires_at`. Keep the
timer going until the player closes: the session ends 5 minutes (the idle timeout) after the last
accepted heartbeat, and at `session_expires_at` whatever the player does (then start a new session
through your backend). A player should also heartbeat when it resumes after a pause or a hidden tab,
and again as soon as it sees a `401` it did not expect.

| Status | When | What the player does |
|---|---|---|
| `200` | Heartbeat recorded. | Use the new token. |
| `401` | Bad token, or the session is revoked, ended, expired or idle. One generic answer, so the status does not say which. | Stop playing and ask your backend for a new session. |
| `429` `rate_limited` | The previous heartbeat was less than `max(heartbeat_interval / 4, 5 s)` ago. | Wait `Retry-After` seconds; nothing was recorded and the old token is still the current one. |

The edge records the heartbeat and checks the session in one atomic database statement: the idle
check uses the **previous** heartbeat time, so a session that has already been idle for 5 minutes
cannot be revived by a late heartbeat. The `429` floor stops a script from minting tokens in a tight
loop: it gets one token per gap, however many requests it sends. Edge signs these tokens with the
HMAC key it already holds to verify them (ADR 0028), so heartbeats add no new secret to the edge role.

The token a heartbeat replaces **keeps working until its own expiry** (tokens are stateless). Only a
revoke or the end of the session stops the session itself. Drop the old token anyway: it adds nothing.

**End.** When the viewer closes the player or the page unloads, send `POST /v1/play/{session_id}/end`
with the token and an empty body (use `fetch(url, {method: "POST", keepalive: true, headers})`, since
`navigator.sendBeacon` cannot set the `Authorization` header). The answer is `204`. The session becomes
`ended` and stops counting against the viewer's concurrency limit, so closing a tab does not use up a
slot for the idle timeout. It is idempotent, and it needs only a valid token for the session: ending a
session that is already ended, idle, expired or revoked is a `204` too, and a revoked session stays
revoked. A bad token is the generic `401`.

Both routes follow the CORS rules above (the preflight allows `POST`) and, like the key endpoint, never
log the token or the session ID.

### Revoking and inspecting sessions

All three operations need the `sessions:write` scope. The session ID arrives in the path in the clear;
the server looks it up by its SHA-256, within your tenant, and never logs it or repeats it in an error.
A session of another tenant, an unknown one and a malformed ID are the same `404 not_found`.

- `GET /v1/playback-sessions/{session_id}` returns
  `{session_id, asset_id, viewer_id, state, created_at, last_heartbeat_at, session_expires_at, ended_at,
  revoked_at, revoke_reason}`; the last three are present only when set. Never a token. `state` is
  `active`, `ended` or `revoked`. A session that is still `active` in storage but idle past the idle
  timeout, or past its maximum age, is reported as `ended` (with no `ended_at` until the sweep records
  it), because it can no longer be used.
- `POST /v1/playback-sessions/{session_id}/revoke` with an optional body `{"reason": "…"}` (at most 200
  printable characters). The reason is stored with the session and returned by the status call:
  **do not put personal data in it**. It returns the status object. The call is idempotent:
  revoking a revoked session is a `200` that keeps the first reason and time. Revoking a session that has
  already **ended** is also a `200` and leaves it `ended`: the record keeps how the session really
  finished, and an ended session cannot be used anyway.
- `POST /v1/playback-sessions/revoke` with `{"viewer_id": "…"}`, `{"asset_id": "ast_…"}` or both (both
  must match), and an optional `reason`, revokes every `active` session of **your tenant** that matches
  and returns `{"revoked": <count>}`. At least one filter is required: an empty body is `400`, so there
  is no tenant-wide revoke by accident. Sessions of other tenants are never touched; an asset that is
  not yours matches nothing. A session that is idle but not yet swept counts, because its stored state
  is still `active`.

A revoke that changes a session, and a bulk revoke that revokes at least one, write an audit event
(`playback_session.revoke`, `playback_sessions.revoke`) with the calling key and the request ID. The
single event names the session by a one-way label (the first 8 bytes of its SHA-256 in hex), never the
ID; the bulk event's target holds the filters and the count. A repeated revoke that finds nothing to do
writes nothing.

**What revocation stops, and when.** Revocation is read from the session row, never cached, so it takes
effect **at once** for playlists, the key endpoint and heartbeats: the next request gets `401`, although
its token still verifies. It does **not** stop segments: a token already issued keeps fetching
segments until it expires (10 minutes by default, and a heartbeat before the revoke may have made it
newer). The segments are unreadable without the key, but a viewer who already fetched the key can
decrypt what they download until then. If that window matters, lower `token_ttl_seconds`.

**Cleanup.** The edge role also marks sessions `ended` when they are idle past their tenant's idle
timeout or past their maximum age, in batches of 1000 (up to 20 batches per run), every ten minutes
and at start-up. This only keeps the stored state honest (every check recomputes the same rule from
the row's times, so nothing waits for the sweep).

### The access trail and the privacy settings

Cipherframe keeps an **access trail**: one row per session event, so you can answer "who played this
asset, and when" and "what happened to this session". It is the only record of viewer activity
(invariant I10): there are no viewer behavioural analytics, and what a viewer watched is never recorded.
(This is not the per-request log line described under [Access log](#access-log) below, which has no
viewer in it.)

- `GET /v1/assets/{asset_id}/access-log` and `GET /v1/playback-sessions/{session_id}/access-log` need the
  `assets:read` scope. Both return `{items, next_cursor}`, **newest first**. Filters: `from` (inclusive)
  and `to` (exclusive) as RFC 3339 times, `event` (one of the events below), `limit` (1 to 500, default
  100) and `cursor` (the opaque `next_cursor` of the previous page; it is present while older rows
  remain). A bad filter is `400` with an `errors` entry; `from` must be before `to`. An asset or session
  of another tenant, a deleted asset and an unknown one are all `404`.
- A row is `{event, at, asset_id, session, viewer_id, auth_method, segments_served, ip, user_agent,
  request_id}`; everything but `event` and `at` is present only when there is a value.
  **`session` is not the session ID** and not its hash: it is the first 4 bytes, in hex (8 characters),
  of SHA-256 of the session's stored hash followed by your tenant ID. It only lets you group the rows of
  one session in the asset's trail, and it cannot be turned back into the ID. Rows never contain a
  session ID or a token.

| Event | Meaning |
|---|---|
| `session_created` | A session started, by API key, JWT or callback. |
| `session_denied` | A session could not start: the viewer's limit was reached, the asset was not ready, or a JWT or callback authorization failed (no `viewer_id`, since nothing vouches for one). Refused authorizations are rate limited per tenant (30 a minute and 300 a minute over all tenants, per edge replica), so a flood of bad requests from the internet cannot fill the trail. |
| `playlist` | The session fetched its master playlist. Media playlists are **not** logged (a player fetches one every few seconds). |
| `key` | The session fetched the content key. |
| `key_denied` | A key request was refused for a session that exists: revoked, ended, expired or idle (the generic `401`), or over a bound (`429`). At most one row per session per minute per edge replica. A token that does not verify names no session and logs nothing. |
| `heartbeat` | A heartbeat was accepted. At most one row per session per 5 minutes per edge replica (the last time is kept in memory, in a table bounded to 10 000 sessions). |
| `end` | The player ended the session (a repeated end is not logged again). |
| `revoked` | The session was revoked through the API. Each session of a bulk revoke gets a row. |
| `expired` | The background sweep ended the session (past its maximum age, or idle). `at` is when the sweep recorded it, up to about 10 minutes after the session stopped being usable. |
| `segments` | How many segment requests the session made in the last flush interval (about 30 seconds); `segments_served` is that count. |

**What is never recorded.** Not which segment, rendition or position was fetched: segment requests are
counted in memory per session (the init segment counts like a media segment) and written as one
`segments` row per session per flush interval, with a count and nothing else. Not the media playlists
fetched, not what the player did. With `delivery: presigned` the player fetches segments from storage
directly and edge never sees them, so there are no `segments` rows. The viewer's own `viewer_id` is
whatever you chose.

**It is best effort.** Requests hand events to a bounded in-memory queue (8192 events) and never wait;
one writer per process inserts them in batches of up to 500, at least once a second. When the queue is
full, or the database keeps refusing a batch (it is retried three times), events are **dropped** and
counted, and a warning is logged at most once a minute. A crash loses what is still queued (about a
second of events and up to 30 seconds of segment counts), a graceful shutdown flushes them with a
5-second limit, and counts for more than 10 000 sessions at once on one replica are dropped. Heartbeat and
`key_denied` limits are per replica, so several replicas can log a little more often. Treat the trail
as an audit aid, not a billing ledger or a complete record. It never slows or fails playback. `expired`
rows are written by the sweeper directly, and a failure to write them is only logged.

**What a row can hold about the viewer's connection.** `ip` (the address of the TCP peer) and
`user_agent` (the `User-Agent` header, cut to 256 characters) are stored **only** when the tenant allows
it, and the default is that nothing is stored. They are recorded only for requests the viewer's own
browser made (playlist, key, heartbeat, end, browser-started creation or refusal), never for
API-key session creation, revocation or expiry, whose caller is your server or nobody. Cipherframe has
no trusted-proxy setting and **never reads `X-Forwarded-For`**, which a client can write: behind a
reverse proxy or load balancer `ip` is the proxy's address, and the proxy's own logs are where the
client address lives.

- `GET /v1/privacy-settings` returns `{store_ip, store_user_agent, keep_source, asset_ttl_seconds,
  updated_at}`: the stored settings, or the defaults (both flags `false`, `keep_source` `true`,
  `asset_ttl_seconds` and `updated_at` absent).
  `PUT /v1/privacy-settings` replaces them (send both flags: a missing one is `400` with an `errors`
  entry; `asset_ttl_seconds` and `keep_source` are optional and leaving one out sets it to its default,
  so a client written before `keep_source` existed cannot switch it off by accident). `keep_source`
  (default `true`) is whether the uploaded original stays in storage after processing (see "Keeping
  the original" above). `asset_ttl_seconds` (60 to
  315360000) is the tenant's default asset time-to-live (see "Retention" above). Both calls need the
  `admin` scope, and a change is written to the audit log (`privacy_settings.update`). The flags apply
  to rows written afterwards (each process caches the settings for up to 30 seconds, and a row is
  written about a second after its request); rows already written are not rewritten, and they are
  removed by the retention window below. When the settings cannot be read, nothing is stored.
- **Retention (M6-4, ADR 0040).** Rows of the trail and the anomaly events are kept for
  `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS` (default 90, 1 to 3650). A scheduled job in the worker role
  (every five minutes) drops each monthly partition that lies entirely before the window, deletes the
  older rows of the partition the window ends in, and deletes older rows of `playback_events`, in
  batches. It never touches newer rows, and it works from any database role (the partition functions
  run with their owner's rights).

**Storage.** The table `playback_access_log` is partitioned by month (UTC). Every sweep of the edge
role creates the partitions of the current month and the next two; there is no default partition, so a
database whose edge role has never run has partitions for the month of the migration and the next one
only, and inserts for a later month fail (and are dropped and logged) until a sweep runs. Dropping old
partitions for retention is a function that exists and is tested (`playback_access_log_drop_partitions_before`)
but is not called by anything: M6 will.

### What the playback endpoints do not protect against

- A token holder can fetch the playlists and segments of that one session until the token expires.
  Segments already downloaded stay decryptable by anyone who also fetched the key.
- Revoking a session stops new playlists, key fetches and heartbeats at once but not segments: a revoked
  session's token still fetches segments until it expires (see above). A viewer who fetched the key
  before the revocation can still decrypt the segments they hold; AES-128 HLS is not DRM (I8).
- The key bounds limit how fast and how often a token can fetch the key. They do not stop an
  authorized viewer from fetching it once and keeping it.
- Edge caches a tenant's settings and the owner of a session for up to 30 seconds. A tenant that
  turns `token_in_url` off, or removes an allowed origin, sees it take effect within that time.
- The preflight answers any well-formed session ID with `204` and looks up its tenant (cached for
  30 seconds, also for IDs that do not exist). Put a rate limit in front of edge, as for any public
  endpoint.
- With `token_in_url` on, the token is in URLs: browser history and the logs of proxies and CDNs you
  do not control can hold it, until it expires.
- With `delivery` set to `presigned` or `cdn`, signed storage or CDN URLs are in the playlists, and so possibly in
  history and intermediary logs, until they expire (at most 10 minutes). They give read access to
  encrypted segments only; the key still needs a valid session.
- The concurrency limit counts sessions per `viewer_id`. A caller that gives each of one person's
  tabs a different `viewer_id` defeats it, so derive the ID from your own user, not per page.
- The limit is not a licensing control: it is checked when a session starts, and heartbeats keep
  sessions alive. A viewer who shares a token still plays only until it expires, but with a heartbeat
  loop can play for the whole session; revoke a session you suspect.
- Anything that can call `POST /v1/playback-sessions` with a `sessions:write` key can start sessions
  for any `viewer_id` of its tenant, up to the limit, for any ready asset of the tenant.
- The access trail is best effort (see above): under overload or a database outage events are dropped,
  so a missing row is not proof that something did not happen.
- The anomaly signals catch a client that behaves unlike a player. They do not catch a careful scraper
  that fetches the key like a player, paces its requests and uses one session per viewer ID; nor a
  viewer who fetched the key once and shares it. `segments_without_key` does nothing in `presigned`
  or `cdn` delivery. See [threat-model.md](threat-model.md#what-the-anomaly-signals-catch-and-miss).
- The access trail records who and when, not what was watched, and its `ip` is the connecting peer,
  which is a proxy's address behind one.

## Browser-started sessions: JWT and signed callback (ADR 0029, 0031)

`POST /v1/playback-sessions` is for your server, with your API key. When the viewer's browser should
start its own session instead, your application authorizes the viewer in one of two ways, and the
browser calls **edge**:

```
POST <edge>/v1/play/tenants/<tenant_id>/sessions
```

The tenant ID (`ten_…`) is in the path because a CORS preflight has no body: edge needs the tenant to
know which origins to allow. It is an identifier, not a secret. The api role stays server-to-server
only. Once the viewer is authorized, the session is created by the same code as
`POST /v1/playback-sessions`: the same asset checks (`404`, `409 asset_not_ready`), the same
per-viewer limit (`409 session_limit`, and these sessions count toward the same limit as API-key
sessions), the same settings and the same `201` body (`session_id`, `token`, `manifest_url`, …). The
response is `Cache-Control: no-store`. The body of the request is

```json
{ "asset_id": "ast_…", "method": "jwt" }
{ "asset_id": "ast_…", "method": "callback", "ticket": "<opaque string from your page>" }
```

**The viewer never chooses the variant.** Your application decides it: for `jwt`, with an optional
`variant` claim (`original` or `masked`); for `callback`, by approving the variant the callback body
names. Without a claim the asset's default applies (`masked` for an asset created with `mask_faces`,
else `original`). The request body may also carry `"variant"`, but only to confirm: a value that
differs from the one your application decided is `403 forbidden`, so a viewer cannot pick `original`
unless the default already is `original`. The `variant` checks of the session (`409
variant_unavailable`, `409 variant_not_ready`) apply as for `POST /v1/playback-sessions`.

A tenant that has configured nothing, a method that is off, a bad token, a callback that refuses, a
replayed token, an unknown tenant: all are the **same generic `401`** (`unauthenticated`, with
`WWW-Authenticate: Bearer`), so the answer says nothing about why. A malformed body is `400`. If
Cipherframe itself fails (the database, or the key provider that wraps the callback secret) the answer
is `5xx`, never a denial and never a grant (I11).

### Configuring a tenant (admin scope)

| Call | What it does |
|---|---|
| `GET /v1/playback-auth` | The settings, the uploaded key IDs and the state of the callback secret. **Never the secret.** |
| `PUT /v1/playback-auth` | Replaces `jwt_enabled`, `jwt_issuer`, `jwt_audiences`, `jwt_jwks_url`, `jwt_viewer_claim` (default `sub`), `callback_enabled` and `callback_url`. A full replacement: a field left out returns to its default. `jwt_enabled` and `callback_enabled` are required. |
| `PUT /v1/playback-auth/jwt-keys/{kid}` | Uploads a public JWK. |
| `DELETE /v1/playback-auth/jwt-keys/{kid}` | Deletes it. |
| `POST /v1/playback-auth/callback-secret/rotate` | Makes a new callback secret and returns it **once**. |

`callback_enabled` needs a callback secret to exist (rotate one first) and `jwt_enabled` needs a
`jwt_jwks_url` or at least one uploaded key. URLs must be `https`, at most 2048 characters, without
credentials or a fragment, and not an IP literal in a blocked range (see the SSRF guard below).
Every change writes an audit event (`playback_auth.update`, `playback_auth.jwt_key.put`,
`playback_auth.jwt_key.delete`, `playback_auth.callback_secret.rotate`) with the calling key and the
request ID, and never a key, URL or secret. Edge reads the JWT settings and uploaded keys through its
30-second cache (see the playback caveats above); it reads the callback settings and secret for every
callback, so a rotation or switching the callback off applies at once.

### JWT

The browser sends the token in `Authorization: Bearer <jwt>`:

```js
const res = await fetch(`${edge}/v1/play/tenants/${tenantId}/sessions`, {
  method: "POST",
  headers: { "Authorization": `Bearer ${jwtFromYourServer}`, "Content-Type": "application/json" },
  body: JSON.stringify({ asset_id: assetId, method: "jwt" }),
});
const { token, manifest_url } = await res.json();   // then play as for any session
```

Sign the token on **your** server, for one viewer and one asset, when the viewer asks to play.

| Requirement | Rule |
|---|---|
| Algorithm | `EdDSA` (Ed25519), `ES256` (P-256) or `RS256` (RSA, at least 2048 bits). `none` and every HMAC algorithm are always refused. A key is used only with the algorithm it was uploaded for (or, from a JWKS, the one its type allows), so a token cannot pick a different one. |
| Key | The header `kid` selects the key: an uploaded key first, then the JWKS. A token without a `kid`, or with an unknown one, is refused. |
| `iss` | Equal to `jwt_issuer`. |
| `aud` | A string or a list; at least one entry must be in `jwt_audiences`. |
| `exp` | Required. At most 60 seconds past it (clock skew). It may be at most 24 hours in the future. |
| `nbf`, `iat` | Honoured if present, with 60 seconds of skew. |
| `jti` | Required, at most 128 characters, and **single use**: it creates at most one session (see below). |
| `asset_id` | Required, equal to the `asset_id` in the request body. |
| `variant` | Optional string, `original` or `masked`: which variant this viewer may play. Absent means the asset's default. Any other value is the generic `401`. |
| viewer | The claim named by `jwt_viewer_claim` (default `sub`) must be a string that is a valid viewer ID: 1 to 128 printable characters, no control characters, and pseudonymous (never an email address). |

**`asset_id` is an implementation detail of ADR 0029**, not in the ADR's list of required claims. Without
it a token your server signed for one video would open every asset of the tenant for as long as it
lives. With it the token is bound to the asset it was signed for. The 24-hour limit on `exp` is the
other addition: a `jti` is remembered until its token's `exp` (plus the skew), so an unbounded `exp`
would be an unbounded row.

**Single use.** Edge records the token's `jti` (as a SHA-256, per tenant) in `playback_jwt_jti` until
`exp` + 60 seconds; the first request wins and a replay, including one that races the first, is the
generic `401`. The jti is recorded **before** the session is created, so a token that then fails with
`409 session_limit` or `409 asset_not_ready` is spent: sign a new one. Rows are deleted by the edge
role's sweeper every ten minutes.

**Keys.** You can upload public keys, give a JWKS URL, or both.

- *Uploaded:* `PUT /v1/playback-auth/jwt-keys/{kid}` with the JWK as the body, `alg` included:
  `{"kty":"OKP","crv":"Ed25519","x":"…","alg":"EdDSA"}`. Refused with `400`: a private key (any
  private member such as `d`), an RSA key under 2048 bits, an EC curve other than P-256, any key type
  other than OKP/Ed25519, EC and RSA (symmetric keys included), an `alg` that is not `EdDSA`,
  `ES256` or `RS256` or does not match the key, a `use` other than `sig`, and a `kid` member that
  differs from the path. A tenant may hold 20 keys (`409` beyond that). The error says what is wrong
  and never quotes the key.
- *JWKS:* edge fetches `jwt_jwks_url` with a 3-second timeout, caches the document for about 10
  minutes, and refetches when a token names an unknown `kid`, **at most once every 30 seconds per
  tenant** (so a stream of bad tokens cannot make Cipherframe hammer your server). The document may
  be at most 64 KiB; keys that cannot be used (unsupported type, short RSA key, no `kid`, a repeated
  `kid`, `use: enc`) are skipped. After a failed refresh, the stale document is not used. Publish a
  new key in the JWKS at least 30 seconds before you sign with it, or upload it.

### Signed callback

With `method: "callback"` the browser sends a `ticket`: an opaque string from your page (1 to 2048
bytes), for example a short-lived login or order reference that only your callback can resolve.
Cipherframe never logs it. Edge then **POSTs to your `callback_url`**:

```
POST /cipherframe/authorize HTTP/1.1
content-type: application/json
webhook-id: msg_8c1f…
webhook-timestamp: 1789000000
webhook-signature: v1,<base64>[ v1,<base64>]

{"type":"playback.authorize","tenant_id":"ten_…","asset_id":"ast_…","variant":"masked","ticket":"…",
 "request_id":"0195c8a2-…","timestamp":"2026-11-11T15:00:00Z"}
```

`variant` is the variant the session would be bound to (`masked` for an asset created with
`mask_faces`, else `original`). Answering `allow: true` approves that specific variant; the viewer's
request cannot ask for another.

Your endpoint answers **HTTP 200** with

```json
{ "allow": true, "viewer_id": "viewer-9" }
```

and that is the only answer that grants. `viewer_id` is validated like any viewer ID. Decoding is
strict: a missing `allow`, an unknown field, a wrong type, trailing data or a body over 8 KiB is a
denial. Everything else is the generic `401`: a timeout (the whole call, connect included, has
**2 seconds**), a network or TLS error, a redirect (never followed), any other status (`202`, `403`,
`500`, …), `allow: false`, a malformed answer. Answers are not cached: every session creation calls
you.

**Verifying the signature** follows [Standard Webhooks](https://www.standardwebhooks.com). The signed
content is `<webhook-id>.<webhook-timestamp>.<raw body>`, the key is the secret's 32 bytes (the base64
after `whsec_`), and each signature is `v1,` plus the base64 of its HMAC-SHA256. Reject a timestamp
more than five minutes from your clock, compare in constant time, and accept the request if **any**
signature in the space-separated header matches. Any Standard Webhooks library does this; in plain
JavaScript:

```js
import { createHmac, timingSafeEqual } from "node:crypto";
function verify(secret, headers, rawBody) {            // secret = "whsec_…"
  const id = headers["webhook-id"], ts = headers["webhook-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const mac = createHmac("sha256", key).update(`${id}.${ts}.${rawBody}`).digest();
  return headers["webhook-signature"].split(" ").some((s) => {
    const [v, b64] = s.split(",");
    const got = Buffer.from(b64 ?? "", "base64");
    return v === "v1" && got.length === mac.length && timingSafeEqual(got, mac);
  });
}
```

**The secret and its rotation.** `POST /v1/playback-auth/callback-secret/rotate` returns
`{"secret": "whsec_…", "version": N}` once. Cipherframe stores it wrapped by the key provider, with
associated data that binds it to your tenant, its purpose and its version, and unwraps it only for the
length of one callback. Rotating again makes a new secret current. **For 24 hours after a rotation the
previous secret keeps signing too**: every callback then carries two signatures, so your endpoint can
accept both secrets while you switch and never refuses a viewer; `GET /v1/playback-auth` shows
`callback_previous_secret_valid_until` while that lasts. After 24 hours the header carries one
signature. If Cipherframe cannot unwrap the secret (a key provider outage, a damaged record) it does
**not** call you and answers `503 dependency_unavailable`: its own outage is never reported as your
denial.

### The outbound request guard

A JWKS URL and a callback URL are chosen by the tenant, so every outbound request is made by an
SSRF-guarded client (`internal/outbound`): `https` only; the **dialed** address is checked after DNS
resolution, on every connection attempt, and loopback, private (RFC 1918 and ULA), link-local
(including `169.254.169.254`), multicast, unspecified, carrier-grade NAT (`100.64.0.0/10`) and other
special-purpose ranges are refused, also in IPv4-mapped, NAT64 and 6to4 forms; redirects are never
followed; environment proxies are ignored; response size is bounded; and errors never carry the URL.
Your endpoints must be publicly reachable. Edge needs outbound HTTPS only for tenants that use a JWKS
URL or a callback.

### CORS

The preflight `OPTIONS /v1/play/tenants/{tenant_id}/sessions` needs no credentials and answers `204`
in every case; `Access-Control-Allow-Origin` (and `Allow-Methods: POST, OPTIONS`,
`Allow-Headers: Authorization, Content-Type`) are added only for an origin listed in the tenant's
`allowed_origins`. The same header is added to the real response, including a `401`, so the page can
read it. Credentials are never allowed.

### What browser-started sessions do not protect against

- A viewer holding a valid JWT (or able to make your callback answer yes) can start sessions for any
  viewer ID your token or callback names, up to the per-viewer limit. The JWT is a bearer credential
  for one asset until it expires: keep `exp` short (a minute is plenty), and sign it only after you
  decided the viewer may watch.
- The endpoint is public and unauthenticated until the token or callback decides, and a callback
  request costs you a call to your endpoint. Put a rate limit in front of edge, and make your callback
  cheap and idempotent. Cipherframe does not rate-limit callbacks per tenant.
- A session creation waits for your callback, up to 2 seconds.
- A JWT is spent as soon as its signature, claims and `jti` check out, even when the session then
  fails with `409`.
- Deleting an uploaded key, or changing the issuer or audiences, applies within the 30-second cache.
  A key you remove from a JWKS keeps verifying until the cached document expires (10 minutes).
- Wrapped callback secrets are not re-wrapped by the KEK rotation job (`kms.rewrap`): a KEK version
  must stay configured while a secret wrapped under it is current or within its 24-hour overlap, or
  rotate the callback secret to re-wrap it.

## Webhooks (ADR 0045)

Cipherframe sends events to HTTPS endpoints you register. All operations need the `webhooks:manage`
scope (an admin key has it) and are audited when they change something.

| Operation | Route | Notes |
|---|---|---|
| `createWebhookEndpoint` | `POST /v1/webhook-endpoints` | `201` with the endpoint and its secret, once |
| `listWebhookEndpoints` | `GET /v1/webhook-endpoints` | `200`, at most 10 items |
| `getWebhookEndpoint` | `GET /v1/webhook-endpoints/{endpoint_id}` | `200` or `404` |
| `updateWebhookEndpoint` | `PATCH /v1/webhook-endpoints/{endpoint_id}` | `url`, `events`, `enabled` |
| `deleteWebhookEndpoint` | `DELETE /v1/webhook-endpoints/{endpoint_id}` | `204`, deliveries go with it |
| `rotateWebhookEndpointSecret` | `POST /v1/webhook-endpoints/{endpoint_id}/rotate-secret` | `200` with the new secret, once |
| `replayDeadWebhookDeliveries` | `POST /v1/webhook-endpoints/{endpoint_id}/replay-dead` | `200` `{"replayed": n}` |
| `listWebhookDeliveries` | `GET /v1/webhook-deliveries` | `endpoint_id`, `status`, `limit`, `cursor` |
| `getWebhookDelivery` | `GET /v1/webhook-deliveries/{delivery_id}` | the delivery and its attempts |
| `replayWebhookDelivery` | `POST /v1/webhook-deliveries/{delivery_id}/replay` | `202`, `409` while pending |

**Endpoints.** `url` must be `https`, without credentials, at most 2048 characters, and must not name a
private, loopback or link-local address (a bad URL is `400`; the error never repeats it). The same
guard as [the outbound request guard](#the-outbound-request-guard) runs again, on the resolved address,
at every delivery. `events` lists the kinds to receive; absent or empty means all six. `enabled`
defaults to `true`; the deliveries of a disabled endpoint wait. A tenant may have 10 endpoints (`409
conflict` beyond that). An endpoint is `{id, url, events, enabled, secret_version,
previous_secret_valid_until, created_at, updated_at}` with `id` as `whe_` and 26 characters.

**Secrets.** The signing secret is returned **once**, by creation and by rotation, as `whsec_` and the
standard base64 of 32 random bytes, with `Cache-Control: no-store`. It is stored wrapped by the key
provider and never returned again. After a rotation the previous secret keeps signing for 24 hours, so
each request carries two signatures until then. Creating and rotating need the key provider (`503
dependency_unavailable` without it).

**Events.** The request is `POST` with a JSON body and the three Standard Webhooks headers:

```
webhook-id: <event id, a UUID; the same on every attempt and replay>
webhook-timestamp: <unix seconds, fresh on every attempt>
webhook-signature: v1,<base64 HMAC-SHA256 of "<id>.<timestamp>.<body>">[ v1,<second signature>]
```

```json
{"id": "0197...", "type": "asset.ready", "occurred_at": "2026-11-15T10:00:00Z",
 "tenant_id": "ten_...", "data": {"asset_id": "ast_...", "state": "ready"}}
```

Verify with any Standard Webhooks library, reject timestamps more than a few minutes old, and
deduplicate on `id`: delivery is at-least-once, in no guaranteed order.

| `type` | When | `data` |
|---|---|---|
| `asset.ready` | processing finished | `asset_id`, `state` |
| `asset.failed` | processing failed or the upload was aborted | `asset_id`, `state`, `failure_code` |
| `asset.deleted` | the verified deletion finished | `asset_id`, `state`, `reason` (`requested` or `retention`) |
| `retention.expired` | the asset's time-to-live ran out and its deletion started | `asset_id`, `state`, `expires_at` |
| `session.revoked` | a playback session was revoked (API, automatic revoke, asset deletion) | `asset_id`, `viewer_id`, `session`, `reason` |
| `session.anomaly` | an anomaly event was raised (`listPlaybackEvents`) | `kind`, `asset_id`, `viewer_id`, `session`, `detail` |

`session` is the 8-character fingerprint the access trail shows, never the session ID. Absent values
are left out. A retention deletion sends `retention.expired`, then `asset.deleted`.

**Delivery.** A request has a 10-second timeout; any response that is not `2xx` (a redirect included,
which is never followed) is a failure. A failed delivery is retried 11 times after 10 s, 30 s, 1 min,
5 min, 15 min, 30 min, 1 h, 2 h, 4 h, 6 h and 8 h (each spread by up to 20%), about 22 hours in all;
after the twelfth failure it is `dead`. A delivery is `{id, endpoint_id, event_id, kind, status,
attempts, last_status_code, last_attempt_at, next_attempt_at, completed_at, created_at}` with `status`
`pending`, `succeeded` or `dead`; `status=dead` is the dead-letter list. `getWebhookDelivery` adds the
attempts: `number`, `at`, `status_code`, `duration_ms`, `error` (`status`, `timeout`, `network`,
`redirect`, `blocked_address`, `bad_url`) and `excerpt`, the start of the response reduced to at most
200 printable ASCII characters. Nothing else of a response is kept.

**Replay.** `replayWebhookDelivery` puts a `succeeded` or `dead` delivery back in the queue with a fresh
attempt budget; `replayDeadWebhookDeliveries` does it for every dead delivery of an endpoint. The event
`id` does not change. Events, deliveries and attempts are removed after the access-trail retention
window (`CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`, default 90 days), so a dead delivery can be replayed
for that long. An endpoint receives only events that happen after it was registered. The CLI wrapper of
this API comes in M8.

## Quotas and usage (ADR 0047)

A tenant, and optionally each of its clients, can be given limits. **Nothing is limited until a limit is
set**: a tenant that never calls these endpoints has no quota, and a limit that is absent is unlimited.
All five operations need the `admin` scope.

| Method and path | What it does |
|---|---|
| `GET /v1/quotas` | The tenant's limits (`{}` while none were set; `updated_at` appears with the first replacement). |
| `PUT /v1/quotas` | Replaces every limit. A field left out is unlimited. |
| `GET /v1/clients/{client_id}/quotas` | One client's overrides (a client of another tenant is `404 not_found`). |
| `PUT /v1/clients/{client_id}/quotas` | Replaces every override. One above the tenant's limit for the same quota is `400 invalid_request` with an `errors` entry for it. |
| `GET /v1/usage` | The tenant's usage next to the limit in force for each quota. With `?client_id=cli_...`, that client's own usage against the lower of its override and the tenant's limit. |

The limits (each at least 1):

| Field | Limits | Counted over | Refused with |
|---|---|---|---|
| `storage_bytes` | Source plus delivery bytes. | The asset registry (`size_bytes`) and the artifact registry, not a listing of storage. A deleted asset stops counting when its purge completes; an aborted upload stops counting at once. For a client: the assets it created. | `409 quota_exceeded`, `limit: storage_bytes`, at `POST /v1/assets` (declared size) and again at `POST /v1/assets/{id}/commit` (verified size; the asset stays `uploading` and can be committed again after room was made). |
| `transcode_minutes_per_month` | Minutes of source processed per calendar month (UTC). | One charge per asset, written when processing starts and the duration is known. | The asset fails with `failure_code` `quota_transcode_minutes` (see below); `commit` itself is not refused. |
| `concurrent_sessions` | Active playback sessions, on top of `max_sessions_per_viewer`. | Sessions that are active, not expired and not idle past the idle timeout. A client's override counts the sessions its own keys made; sessions the viewer's browser started (JWT, callback) count toward the tenant's limit only. | `409 quota_exceeded`, `limit: concurrent_sessions`, at `POST /v1/playback-sessions` and `POST /v1/play/tenants/{tenant_id}/sessions`. |
| `requests_per_minute` | Requests per minute per API key on the api listener. | A token bucket per key, in memory: a minute's worth can be used at once. | `429 rate_limited` with `Retry-After` (whole seconds, at least 1). |

Notes:

- **Replacing, not patching.** Send every limit you want; the rest become unlimited (or, for a client, no
  override). A lower limit never deletes assets or ends sessions: it refuses what comes next, and a tenant
  can be over a limit it just lowered.
- **The lower limit wins.** A client is held to the lower of its override and the tenant's limit, so lowering
  the tenant's limit later applies to every client.
- **Over-quota transcoding fails the asset.** The duration is only known after the worker has probed the
  source, so a month with no minutes left shows up after the upload: the asset becomes `failed` with
  `failure_code` `quota_transcode_minutes` (and an `asset.failed` webhook), nothing is processed, and the
  upload has to be repeated as a new asset after the month turns or the limit is raised. A retry of an
  asset that was already charged is free. Read `GET /v1/usage` first to know how much is left.
- **Storage can overshoot slightly.** Delivery bytes appear while an asset is processed and are not checked
  there, so the tenant can pass its limit by the output of the assets then in flight; the next creation or
  commit sees it.
- **The request rate limit is per api process instance**, so N instances allow a key up to N times the limit.
  A key reads its limit at most every 15 seconds, so a change reaches a running instance within that time.
  A request that does not authenticate is `401` and is never counted.
- **Usage response.** `storage_bytes`, `transcode_milliseconds` (this month, UTC, from `month_start`; its
  limit is `transcode_minutes_per_month` converted to milliseconds) and `concurrent_sessions` each hold
  `used` and, when limited, `limit`. `requests_per_minute` is the limit in force; request counts are not
  reported.
- Changes are audited (`quotas.update`, `client_quotas.update`) with the caller and no values. Metrics
  for usage and refusals wait for the observability stack ([roadmap](roadmap.md)).

### What the quota endpoints do not protect against

- **A tenant's own keys.** Limits are per tenant and per client; a client with a `sessions:write` key can use
  the tenant's whole session allowance unless its override says otherwise.
- **Abuse of unauthenticated endpoints.** The request rate limit starts after authentication and covers the
  api listener only; the edge has its own per-session limits ([playback](#playback-sessions-and-settings-adr-0028-0030)).
- **A burst across instances.** See the per-instance note above.

## Overlay watermark (ADR 0043, 0048)

The overlay is text the **player draws over the video**: the session code and the viewer's current UTC time,
moving slowly across the frame. It is never burned into the video (every viewer gets the same bytes). It is
**deterrence only**: it tells a viewer that a recording can be traced, and shows when it was made, but anyone
who controls the player, or who films the screen with the overlay cropped or masked, can remove it. It is
not a security control and Cipherframe does not claim it stops a leak.

| Method and path | Scope | What it does |
|---|---|---|
| `GET /v1/overlay-settings` | `admin` | The tenant's settings (the defaults, with the overlay off, until the first `PUT`; `updated_at` appears with it). |
| `PUT /v1/overlay-settings` | `admin` | Replaces every setting. A missing field is `400 invalid_request` with an `errors` entry; so is an invalid value. Audited as `overlay_settings.update`; applies to sessions created afterwards. |
| `GET /v1/overlay-codes/{code}` | `assets:read` | Maps a code seen in a leaked recording to the tenant's sessions (below). |

**Settings.**

| Field | Default | Rule |
|---|---|---|
| `enabled` | `false` | Return `overlay` in session responses. |
| `template` | `{session_code} {date} {time} UTC` | 1 to 120 characters of plain text. Only `{session_code}`, `{date}` and `{time}` are placeholders, at least one must be present, and any other `{` or `}` is refused (an unknown placeholder is an error, never passed through). No control characters, line breaks, other format or separator characters, `<`, `>` or `&`. |
| `opacity` | `0.25` | 0.05 to 0.8. |
| `font_size_fraction` | `0.03` | 0.015 to 0.1: the text height as a fraction of the video height. |
| `color` | `#FFFFFF` | `#RRGGBB`, upper-case hexadecimal. |

There is no placeholder for the viewer ID, a name, an email or any other per-session text from your
application, so nothing about a person can reach the screen through the overlay.

**In the session response.**

```json
"overlay": {
  "template": "K7QH2M9X {date} {time} UTC",
  "session_code": "K7QH2M9X",
  "style": {"opacity": 0.25, "font_size_fraction": 0.03, "color": "#FFFFFF"},
  "drift": {"algorithm": "lissajous-v1", "seed": "94027ae60bbd3256", "period_seconds": 240, "margin": 0.02}
}
```

- `template` has `{session_code}` already replaced; the player replaces `{date}` with the viewer's current
  UTC date (`YYYY-MM-DD`) and `{time}` with the UTC time (`HH:MM:SS`, refreshed at least every second), and
  draws the result as **plain text** (never as markup). `session_code` is also given on its own, for a
  support screen.
- The player moves the text along the path of `drift`, which depends only on `seed`: the same session always
  gets the same path and different sessions get different ones. The algorithm and the conformance vectors
  are in [spec/test-vectors/overlay](../spec/test-vectors/overlay/README.md); the Go reference is
  `internal/overlay`.
- The `seed` and the code are one-way derivations of the session, unrelated to the session ID and the token:
  they cannot be used to play, heartbeat, end or revoke the session.

**Tracing a leaked code.** `GET /v1/overlay-codes/K7QH2M9X` (case is ignored) returns
`{"sessions": [{"asset_id", "viewer_id", "auth_method", "state", "created_at", "session_fingerprint"}]}`:
your viewer ID, the asset and the fingerprint the [access trail](#the-access-trail-and-the-privacy-settings)
shows on every row of the session, so you can read what that session did. The code is 40 bits, so a second
session can match by chance (the list says so); another tenant's code, an unknown code and a code **past the
access-trail retention window** (90 days by default) give an empty list: the worker's retention job forgets
the code of sessions older than the window. A malformed code is `400 invalid_request`.

### What the overlay does not protect against

- **A viewer who controls the player.** The overlay is drawn client-side; a modified player, a browser
  extension or a screen filter removes it. A recording made after cropping it out carries nothing.
- **A leak found after the window.** Past the retention window the code cannot be traced.
- **A code seen only in part.** Eight characters are shown; a partly legible code can match no session or,
  rarely, several.

## Audit log export (ADR 0058)

`GET /v1/audit-events` (scope `admin`) returns the audit events of the caller's tenant as structured
objects, oldest first, for shipping to a log store.

| Query | Meaning |
| --- | --- |
| `limit` | Page size, 1 to 500 (default 100). |
| `after` | The `next_cursor` of the previous page. Opaque; a bad one is a 400. |
| `since`, `until` | RFC 3339 time range on the event time: `since` inclusive, `until` exclusive, `until` after `since`. |

```json
{"items": [{"id": "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f36", "action": "key.rotate", "target": "key_...",
            "client_id": "cli_...", "key_id": "key_...", "request_id": "01...", "created_at": "2026-11-22T10:00:00Z"}],
 "next_cursor": "..."}
```

Follow `next_cursor` (pass it as `after`) until it is absent. Order is `(created_at, id)`, so a page
never repeats or skips a row that was committed before you began. `target`, `client_id`, `key_id`
and `request_id` are absent when the event has none (events the system raises on its own have no
client or key). The log holds IDs, labels and short summaries only: never a token, a key secret, a
signed URL, a session ID (a short fingerprint of one at most) or a source object key.

One limit: an event is stamped when its transaction starts, so one that commits late can carry an
older time than events you already read. When you export on a schedule, start each run a little
before the end of the previous one and drop duplicates by `id`. The command line tool does the
paging: `cipherframe audit export` ([usage.md](usage.md)).

## Integrity signing keys (ADR 0033)

Manifests and deletion records are signed with Ed25519 keys that belong to the deployment, not to a
tenant. See [integrity.md](integrity.md#signing-keys) for custody, rotation and retirement.

| Operation | Route | Scope |
|---|---|---|
| `listSigningKeys` | `GET /v1/signing-keys` | `admin` |
| `rotateSigningKey` | `POST /v1/signing-keys/rotate` | `admin` |
| `retireSigningKey` | `POST /v1/signing-keys/{key_id}/retire` | `admin` |
| `getSigningKeySet` | `GET /.well-known/cipherframe-keys.json` | none |

A key is returned as `key_id` (`sk_` and 26 characters), `algorithm` (`ed25519`), `state`
(`active` or `retired`), `current` (true for the one signer), `public_key` (raw 32 bytes, standard
base64), `created_at`, `activated_at` and `retired_at`. Only public data is ever returned.

- `rotateSigningKey` answers `201` with the new current key. The previous key stays `active`. When the
  key provider is unavailable it answers `503 dependency_unavailable` and creates nothing.
- `retireSigningKey` answers `200` with the retired key, `409 conflict` for the current key, and
  `404 not_found` for an unknown id. Retiring a retired key is a no-op. A retired key stays in both
  lists, so records it signed still verify.
- Rotation and retirement are audited against the caller's tenant (`signing_key.rotate`,
  `signing_key.retire`), with the key id as the target.
- `getSigningKeySet` is served by the edge (the public listener) and by the api listener. It needs no
  key, answers with `Cache-Control: public, max-age=300` and `Access-Control-Allow-Origin: *`, and
  lists every key with `keyid`, `alg`, `public_key`, `status`, `created_at` and, for a retired key,
  `retired_at`, oldest first. A change shows up within a minute (a 60-second in-process cache). If
  the database cannot be read it answers `503`; it never answers an empty set.

## Integrity: manifests, proofs, verify (ADR 0033, 0039)

Every ready asset has a signed manifest (see [integrity.md](integrity.md)). These four operations
serve it, return its optional timestamp token, prove one artifact against it and answer "is this
file ours?". All need `assets:read` and
are tenant-scoped: an asset of another tenant behaves as if it did not exist. The signing keys they
rely on are public (`getSigningKeySet`); the offline verifier (M5-4) needs nothing else.

| Operation | Route | Scope |
|---|---|---|
| `getAssetManifest` | `GET /v1/assets/{asset_id}/manifest` | `assets:read` |
| `getAssetManifestTimestamp` | `GET /v1/assets/{asset_id}/manifest/timestamp` | `assets:read` |
| `getAssetProof` | `GET /v1/assets/{asset_id}/proof?path=&variant=` | `assets:read` |
| `verifyArtifact` | `POST /v1/verify` | `assets:read` |

**Manifest.** `GET /v1/assets/{asset_id}/manifest` returns the stored DSSE envelope with
`Content-Type: application/vnd.cipherframe.manifest+json; profile=dsse`. The envelope's `payload`
(base64) is the canonical manifest, including the `masked` section once the masked variant is
published; the envelope is re-signed when that happens, so fetch it again afterwards. It is
`404 not_found` for an unknown asset, one that is not ready and one without a manifest.

```sh
curl -s -H "Authorization: Bearer $CF_KEY" \
  https://api.example.com/v1/assets/$ASSET/manifest -o manifest.json
jq -r .payload manifest.json | base64 -d | jq '.top_level.root'
```

**Timestamp.** `GET /v1/assets/{asset_id}/manifest/timestamp` returns the RFC 3161 token that
anchors the asset's current manifest (ADR 0041), when `CIPHERFRAME_TSA_URL` is configured and the
authority has answered:

```json
{
  "token": "MIIL…",
  "gen_time": "2026-11-14T10:15:30Z",
  "tsa_url": "https://tsa.example.com/rfc3161",
  "imprint_sha256": "9f2c…"
}
```

`token` is the base64 DER TimeStampToken and `imprint_sha256` is the hex SHA-256 of the manifest's
decoded `payload`, which is what the token stamps. Save the response as `ts.json` and give it to
`cipherframe verify --timestamp`. The manifest endpoint is unchanged. Errors: `404 not_anchored`
when the manifest has no token yet (anchoring is off, the authority has not answered, or the
manifest was just re-signed and its new token is pending), `404 not_found` for an unknown asset, one
that is not ready and one without a manifest.

**Proof.** `GET /v1/assets/{asset_id}/proof?path=720p/seg-0.m4s` proves one artifact. `path` is the
manifest path, relative to the variant's HLS prefix (the same form as the URIs in the master
playlist, never a storage key); `variant` is `original` (default) or `masked`. A segment or init
segment is proven in its rendition tree and that tree's root in the top-level tree; a playlist only
in the top-level tree, so the rendition members are absent. The proof is computed from the signed
manifest, not from storage. Hashes are lowercase hex.

```sh
curl -s -H "Authorization: Bearer $CF_KEY" \
  "https://api.example.com/v1/assets/$ASSET/proof?path=720p/seg-0.m4s"
```

```json
{
  "asset_id": "ast_00000000000000000000000001",
  "variant": "original",
  "path": "720p/seg-0.m4s",
  "sha256": "bb00000000000000000000000000000000000000000000000000000000000000",
  "size": 1048592,
  "leaf_index": 1,
  "tree_size": 3,
  "rendition": "720p",
  "rendition_root": "dd00000000000000000000000000000000000000000000000000000000000000",
  "audit_path": [
    "aa00000000000000000000000000000000000000000000000000000000000000",
    "cc00000000000000000000000000000000000000000000000000000000000000"
  ],
  "top_level": {
    "leaf_index": 0,
    "tree_size": 3,
    "audit_path": [
      "ee00000000000000000000000000000000000000000000000000000000000000",
      "ff00000000000000000000000000000000000000000000000000000000000000"
    ],
    "root": "1100000000000000000000000000000000000000000000000000000000000000"
  }
}
```

To check it, hash the file (`sha256sum`), then follow the audit-path rules in
[integrity.md](integrity.md#hashing-and-merkle-trees-rfc-9162-section-21): the leaf is
`SHA-256(0x00 || sha256(file))`, the path must lead to `rendition_root`, and then
`SHA-256(0x00 || rendition_root)` through `top_level.audit_path` must lead to `top_level.root`, which
must equal the root in the signed manifest (`top_level.root`, or `masked.top_level.root` for the
masked variant). The sizes come from the proof, so only trust a proof once its root matches the
verified manifest.

Errors: `404 artifact_not_found` for a path that is not in the manifest, `404 not_found` for the
asset, `400 invalid_request` for a missing `path` or an unknown `variant`, `409 variant_unavailable`
for `variant=masked` on an asset created without `mask_faces`, and `409 variant_not_ready` when
masking was requested but the masked variant is not published yet.

**Verify.** `POST /v1/verify` compares a hash you computed locally with what was signed; the server
never receives the file. The answer is always `200` with an `outcome`:

- `ours`: the artifact is in the signed manifest and the hash matches. The response adds the
  `proof`.
- `modified`: the `path` is in the signed manifest but the hash differs ("a modified version of
  ours").
- `cannot_say`: anything else, with a `reason` of `no_match` (no such asset, path, variant or hash
  for this tenant, or the asset is not ready) or `manifest_unverifiable` (the stored manifest's
  signature did not verify against the published keys, or it could not be read; the server logs an
  error). It never means "modified".

```sh
H=$(sha256sum seg-0.m4s | cut -d' ' -f1)
curl -s -H "Authorization: Bearer $CF_KEY" -H 'Content-Type: application/json' \
  -d "{\"asset_id\": \"$ASSET\", \"path\": \"720p/seg-0.m4s\", \"sha256\": \"$H\"}" \
  https://api.example.com/v1/verify
```

```json
{"outcome": "ours", "asset_id": "ast_00000000000000000000000001", "variant": "original",
 "path": "720p/seg-0.m4s", "proof": {"...": "as above"}}
```

With only `{"sha256": "..."}` the tenant's registered artifacts are searched. A hit is `ours` with
`asset_id`, `variant` and the manifest `path` (and the proof), confirmed against the asset's signed
manifest; no hit is `cannot_say`, because a hash alone can never prove `modified`. `sha256` must be 64
lowercase hex digits; `asset_id` and `path` go together, and `variant` (default `original`) needs
both; anything else is `400 invalid_request`. The signature of the stored manifest is verified on every
call with the published keys, so a rotated or retired key keeps working while it is published.

## Conventions

### ID formats (ADR 0011)

An object ID is `<prefix>_<26 characters>`: a UUIDv7 written as lowercase Crockford base32
(alphabet `0123456789abcdefghjkmnpqrstvwxyz`, no padding). Parsing is strict: lowercase only, exact
length, and canonical (re-encoding must reproduce the input). An ID with the wrong prefix for its
endpoint is rejected before any query runs. Text order matches creation order.

| Object | Prefix | Example |
|---|---|---|
| Tenant | `ten` | `ten_01k9z3m5q8r7s2t4v6w8x0y1zg` |
| Client | `cli` | `cli_01k9z3m5q8r7s2t4v6w8x0y1zg` |
| API key | `key` | `key_01k9z3m5q8r7s2t4v6w8x0y1zg` |
| Asset | `ast` | `ast_01k9z3m5q8r7s2t4v6w8x0y1zg` |
| Signing key | `sk` | `sk_01k9z3m5q8r7s2t4v6w8x0y1zg` |
| Session | `ses` | `ses_` followed by 52 characters (256 random bits) |

Session IDs are random, unordered and carry no time component. They are capabilities: whoever holds
one can use it, so never log or share them.

### Errors (ADR 0012)

Errors use RFC 9457 `application/problem+json`:

```json
{
  "type": "urn:cipherframe:error:not_found",
  "title": "Not found",
  "status": 404,
  "detail": "Asset not found.",
  "code": "not_found",
  "retryable": false,
  "request_id": "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35"
}
```

`code` is the stable identifier to switch on; `detail` is for people and may change. `retryable`
says whether repeating the same request may succeed. Unexpected failures are always reported as
`internal_error` with the generic detail `An internal error occurred.`; their cause is logged
server-side only.

| Code | Status | Retryable | Meaning |
|---|---|---|---|
| `invalid_request` | 400 | no | The request is malformed or fails validation (including a malformed ID). |
| `unauthenticated` | 401 | no | Credentials are missing or invalid. |
| `forbidden` | 403 | no | The caller is authenticated but not allowed to do this. |
| `not_found` | 404 | no | The object does not exist, or is not visible to the caller. |
| `method_not_allowed` | 405 | no | The path exists but does not support this HTTP method. |
| `conflict` | 409 | no | The request conflicts with the current state of the object. |
| `payload_too_large` | 413 | no | The request body exceeds the allowed size. |
| `asset_not_ready` | 409 | no | The operation needs a `ready` asset and this one is not (yet). |
| `session_limit` | 409 | no | The viewer already has the tenant's maximum number of active playback sessions. |
| `quota_exceeded` | 409 | no | The request would pass a tenant or client quota; the `limit` member names it (see [Quotas and usage](#quotas-and-usage-adr-0047)). |
| `variant_unavailable` | 409 | no | A session or proof asked for the masked variant of an asset created without `mask_faces`. |
| `variant_not_ready` | 409 | no | A session or proof asked for the masked variant (or it is the default) and it is not `ready`. |
| `artifact_not_found` | 404 | no | A proof was requested for a path that is not an artifact of the asset's signed manifest. |
| `not_anchored` | 404 | no | The manifest has no RFC 3161 timestamp token (anchoring is off, or the token is still pending). |
| `not_deleted` | 404 | no | A deletion record was requested for an asset that has not been deleted (yet). |
| `rate_limited` | 429 | yes | Too many requests; retry after the `Retry-After` seconds. |
| `internal_error` | 500 | no | An unexpected server error. |
| `dependency_unavailable` | 503 | yes | A backing service (storage, database, key service) is unavailable. |
| `timeout` | 504 | yes | The operation did not finish in time. |

Some `invalid_request` answers also carry an `errors` array with one `{"field", "message"}` entry per
invalid field (for example `{"field": "allowed_origins[1]", "message": "must be an origin such as
https://example.com"}`). Messages are fixed text and never quote what was submitted.

A `quota_exceeded` answer carries a `limit` member: `storage_bytes`, `transcode_minutes_per_month`,
`concurrent_sessions` or `requests_per_minute`. It is a fixed name; the problem never holds a usage figure,
a limit value or anything about another client or tenant.

Adding a code is compatible; renaming or removing one is breaking. The registry is published as an
enum in the OpenAPI spec.

### Request IDs

Every request gets a UUIDv7 request ID. It is returned in the `X-Request-Id` response header and in
the `request_id` member of error bodies, and is attached to every server log line for that request.
Quote it in support requests.

A caller may send its own `X-Request-Id`. It is kept only if it is a valid UUID in the 36-character
hyphenated form (normalised to lowercase); anything else is replaced by a new UUIDv7, so a caller
cannot put arbitrary text into logs or response headers. Every listener answers errors raised by
the router (unknown path `404 not_found`, wrong method `405 method_not_allowed` with an `Allow`
header), recovered panics (`500 internal_error`) and request-binding failures
(`400 invalid_request`) as `application/problem+json`, never as framework text.

### Access log

Each request produces one structured log line with the method, the matched route pattern (for
example `GET /readyz`), the status, the duration and the request ID. It never contains the query
string, the request path, any request header (so never `Authorization`) or a request body. A request
that matches no route logs the route as `unmatched`.

## What this does not protect against

- Health and readiness are unauthenticated on every listener. Anyone who can reach the port learns
  that the service is running, its check names, and whether each dependency is up or down. Do not
  expose the api listener to the internet; the edge listener is the browser-facing one.
- The access log identifies endpoints and outcomes, not callers: it has no client address or
  credential. Correlate with the request ID, and use your proxy's logs for client addresses.
- The contract test checks that the code and the spec agree on what is implemented. It does not
  fuzz the API, and it cannot tell whether an endpoint is correct, only whether it matches its
  description.

- IDs are not secret. Knowing an object ID grants nothing by itself; access is decided by
  authentication and authorization, never by an ID being hard to guess. Only session IDs are
  secrets.
- UUIDv7 encodes the creation time to the millisecond, so object IDs reveal roughly when an object
  was created. Session IDs do not.
- The prefix check catches a wrong-type ID early; it is not an authorization check.
- `detail` is written to be safe to show, but callers should not parse it. `retryable` is advice:
  retrying a non-idempotent request can still cause duplicates unless an idempotency mechanism
  says otherwise.

- A leaked API key grants its scopes' control-plane access until it is revoked or its rotation overlap ends.
- The control plane does not decide who may watch what; the embedding application does.
