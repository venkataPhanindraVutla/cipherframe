# API

> Status: health and readiness (M1-6); authentication, clients and API keys (M1-7). Asset endpoints arrive with later tasks.

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
| `GET /v1/assets`, `GET /v1/assets/{asset_id}` | yes | no | `assets:read` |
| `POST /v1/assets/{asset_id}/commit`, `POST /v1/assets/{asset_id}/abort` | yes | no | `assets:write` |
| `POST /v1/playback-sessions` | yes | no | `sessions:write` |
| `GET /v1/playback-sessions/{session_id}` | yes | no | `sessions:write` |
| `POST /v1/playback-sessions/{session_id}/revoke`, `POST /v1/playback-sessions/revoke` | yes | no | `sessions:write` |
| `GET /v1/playback-settings`, `PUT /v1/playback-settings` | yes | no | `admin` |
| `GET /v1/play/{session_id}/master.m3u8`, `GET /v1/play/{session_id}/{rendition}/media.m3u8` | no | yes | playback token (`manifest`) |
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
| `assets:read` | Read assets, status, deletion records |
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

An asset goes `created → uploading → committed → processing → ready | failed` (and `deleted` later).
The API never receives media: the embedding application creates the asset, hands the browser the
upload instructions, and commits when the upload is done. The source is never addressable: no
response, header or log line contains its object key or the source bucket's name, and no presigned
URL is ever returned.

**Create.** `POST /v1/assets` with `{"size_bytes": 1073741824, "content_type": "video/mp4",
"upload_method": "tus"}` (`tus` or `multipart`; `content_type` is optional). `size_bytes` must be
exact and at most `CIPHERFRAME_MAX_SOURCE_BYTES` (default 10 GiB; `413 payload_too_large`). No file
name is accepted or stored. The `201` answer, `Cache-Control: no-store`:

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
of another tenant is `404`, never `403`.

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

## Playback sessions and settings (ADR 0028, 0030)

Endpoint names and shapes are flagged for owner review before v1.0.0. This section covers the
control plane, the edge playlist, segment and key routes, and the session lifecycle: heartbeat, end
and revoke (below).

**Start a session.** `POST /v1/playback-sessions` (scope `sessions:write`) with
`{"asset_id": "ast_…", "viewer_id": "u-8f3a…"}`. The asset must belong to your tenant and be `ready`.
The `201` answer, `Cache-Control: no-store`:

```json
{
  "session_id": "ses_…",
  "token": "v1.…",
  "token_expires_at": "2026-11-12T10:10:00Z",
  "heartbeat_interval_seconds": 60,
  "session_expires_at": "2026-11-12T14:00:00Z",
  "manifest_url": "https://media.example.com/v1/play/ses_…/master.m3u8",
  "token_transport": "header"
}
```

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
| `409` | `session_limit` | The viewer already has the maximum number of active sessions. |

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

`allowed_origins` entries are exact origins as a browser writes them: `https://host[:port]`, or
`http://localhost[:port]` for development. Lower case, no path, no trailing slash, no wildcard, no
user information, and no port that is the scheme's default (`https://example.com`, not
`https://example.com:443`). Duplicates are rejected. An invalid request is `400 invalid_request` with
one `errors` entry per field, for example `allowed_origins[1]`, and nothing is stored. A change
applies to new sessions, and edge picks up `token_in_url`, `allowed_origins` and `idle_timeout_seconds`
within 30 seconds (its settings cache).

**Token in URLs (`token_in_url`).** Off by default, so no URL carries a token (pitfall 9). Turn it on
only for tenants that must support native HLS players (for example Safari on iOS) that cannot set
headers: `manifest_url` then ends in `?t=<token>` and `token_transport` is `url`. The token can then
appear in browser history and in the logs of proxies and CDNs that you do not control; it lasts at
most the token TTL, and revoking the session still stops key fetches. Edge strips the parameter from
what it logs and sends `Referrer-Policy: no-referrer` (ADR 0030).

### Playlists and segments on edge (ADR 0027, 0030)

Four `GET` routes on the edge listener serve a session. The player starts at `manifest_url` and
follows the URIs in the playlists; it never builds a URL itself.

| Route | Scope | Returns |
|---|---|---|
| `/v1/play/{session_id}/master.m3u8` | `manifest` | The master playlist. Each variant URI is `<rendition>/media.m3u8`. |
| `/v1/play/{session_id}/{rendition}/media.m3u8` | `manifest` | One rendition's media playlist. |
| `/v1/play/{session_id}/{rendition}/{file}` | `segment` | `init.mp4` (`video/mp4`) or `seg-<n>.m4s` (`video/iso.segment`), streamed from the delivery bucket with `Content-Length`. |
| `/v1/play/{session_id}/key` | `key` | The 16-byte AES-128 content key, raw (`application/octet-stream`). See below. |

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

**Anomaly events.** The first time a token is over its bound, one `key_replay` event is recorded; the
first request past the per-minute bound in a window records one `key_rate` event. Later rejected
requests for the same token or window record nothing. An event holds the tenant, the SHA-256 of the
session ID, the asset ID, the time and the bound; no token and no session ID. (Reading events is a
later task, M4-9.)

**Cleanup.** The per-token counters live in `playback_key_fetches`, one row per token that asked for a
key. The edge role deletes the rows of tokens that expired more than five minutes ago, every ten
minutes (and once at start-up), so the table stays about as large as the tokens of the last
`token_ttl_seconds` plus a few minutes.

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
- The concurrency limit counts sessions per `viewer_id`. A caller that gives each of one person's
  tabs a different `viewer_id` defeats it, so derive the ID from your own user, not per page.
- The limit is not a licensing control: it is checked when a session starts, and heartbeats keep
  sessions alive. A viewer who shares a token still plays only until it expires, but with a heartbeat
  loop can play for the whole session; revoke a session you suspect.
- Anything that can call `POST /v1/playback-sessions` with a `sessions:write` key can start sessions
  for any `viewer_id` of its tenant, up to the limit, for any ready asset of the tenant.

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
| `rate_limited` | 429 | yes | Too many requests; retry later. |
| `internal_error` | 500 | no | An unexpected server error. |
| `dependency_unavailable` | 503 | yes | A backing service (storage, database, key service) is unavailable. |
| `timeout` | 504 | yes | The operation did not finish in time. |

Some `invalid_request` answers also carry an `errors` array with one `{"field", "message"}` entry per
invalid field (for example `{"field": "allowed_origins[1]", "message": "must be an origin such as
https://example.com"}`). Messages are fixed text and never quote what was submitted.

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
