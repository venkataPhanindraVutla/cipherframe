# Architecture

> Status: skeleton (M0-4). Sections marked *pending* depend on open decision gates.

## Purpose

Cipherframe sits between private S3-compatible object storage and a browser. An embedding
application decides who may watch what. Cipherframe turns a source video into encrypted HLS, issues
short-lived revocable playback sessions, records access, signs what it produced, and deletes
verifiably.

## Roles

| Role | Responsibility |
|---|---|
| Control plane (`api`) | Assets, uploads, sessions, keys, deletion records, webhooks, quotas. Server-to-server only. |
| Data plane (`edge`) | Session-scoped playlists, the key endpoint, segment delivery (`proxy` or `presigned`). Browser-facing. |
| Worker | Probe, transcode, package, encrypt, hash, sign, purge, retention sweeps. Runs FFmpeg and FFprobe as separate processes. |
| CLI | Operator and integration tooling, including a public-key-only verifier. |
| Reference player | Demo browser player that attaches the session token to every request. |

Whether these are separate binaries or one binary with roles is **pending (P4)**.

## Storage

- A **source** bucket holds originals. Nothing served by Cipherframe references it (invariant I4).
- A **delivery** bucket holds encrypted segments, playlists and derived artifacts.
- Media bytes do not flow through the control plane in recommended configurations (I9).

### The storage port

All object access goes through `internal/storage` (ADR 0014). `storage.New` returns `Buckets{Source,
Delivery}`, each a `Store` (the delivery one is a `DeliveryStore`, see below): put, get (optionally a byte range), head, list with a continuation cursor,
batch delete, presigned PUT, and multipart upload (presigned parts for servers, and `UploadPart`,
which streams a part from a request body). Bodies are streamed;
library code never holds a whole object in memory. Creating buckets, ACLs, lifecycle rules and
versioning are not part of the port; they belong to deployment.

**Two clients.** An *internal* client (`CIPHERFRAME_S3_ENDPOINT`) makes every server-side call. A
*public* client (`CIPHERFRAME_S3_PUBLIC_ENDPOINT`, default the internal endpoint) is used only to sign
URLs, because a presigned URL's signature covers the host and a browser cannot use an internal
address. Credentials follow the three configuration states: a static key pair, the SDK default chain
(an empty variable), or anonymous (development only).

**Presigned reads exist only for delivery (I4).** `PresignGet` is not on `Store`. It is on
`GetPresigner`, which only the delivery bucket's handle implements (`DeliveryStore = Store +
GetPresigner`), so no code that holds the source bucket can sign a read URL; a test asserts the
source handle does not implement it.

**Key layout.** `internal/storage/keys` is the only code that builds keys. They hold typed IDs and fixed
names, never user-supplied text:

| Bucket | Key |
|---|---|
| source | `t/<tenant>/a/<asset>/source/<128 random bits, hex>` (stored on the asset row, never derivable from IDs) |
| delivery | `t/<tenant>/a/<asset>/…` (playlists, init and media segments, poster) |

`keys.AssetPrefixes` returns the prefix deletion must enumerate in each bucket. It lives beside the
key builders, and a test checks that every key built for an asset falls under one of them.

**Errors.** A storage error has a kind, the operation and the bucket role, and never an object key, a
URL or a credential. Kinds: `NotFound`, `PermissionDenied`, `Timeout`, `Unavailable`, `Invalid`,
`Other`; each has an `errors.Is` sentinel. Anything not positively recognised is `Other`, never
`NotFound`. `storage.ToAppError` maps them to API error codes (`PermissionDenied` becomes
`internal_error`, because wrong storage credentials are an operator problem). `DeleteBatch` sends 1000
keys per request and fails if S3 reports any per-key error inside a successful response.

**What the storage layer does not protect against.**

- Compromise of the operator's storage credentials. Whoever holds them can read, change or delete
  every object in both buckets; encryption of segments (see [encryption.md](encryption.md)) limits
  what the delivery bucket reveals, not what a holder of the credentials can destroy.
- Leaked presigned URLs. A presigned URL is a bearer token: anyone who has it can use it until it
  expires, and it cannot be revoked early. Keep lifetimes short and never log them; `PresignedRequest`
  redacts the URL when printed or marshalled.
- A source object's presigned URL for upload exposes that one key for writing until expiry; the port
  does not check what a client sends to it.
- Differences between S3-compatible stores. The conformance suite runs against SeaweedFS in CI and,
  when you provide credentials, against real S3 or R2; passing it is the only evidence of
  compatibility. `Head` cannot tell a missing bucket from a missing object, because S3 sends no body
  on HEAD.

### Upload data flow (ADR 0025, 0026)

```text
embedding app --API key--> api   POST /v1/assets        creates the asset (created), the S3 multipart
                                                         upload (multipart only) and an upload token
browser ------upload token--> edge  tus  POST/HEAD/PATCH /v1/uploads/tus/...          (tusd, S3 store)
browser ------upload token--> edge  PUT  /v1/uploads/multipart/{asset}/parts/{n}      (streamed UploadPart)
                              edge  ----S3----> source bucket   <source key>[.info|.part]
embedding app --API key--> api   POST /v1/assets/{id}/commit    multipart: complete the upload; both:
                                                                 Head the object, check the size, then in
                                                                 one transaction: committed + enqueue
                                                                 asset.process {tenant_id, asset_id}
```

All upload bytes pass through `edge`; no response, header or log line names the source object key,
the source bucket or an object-store upload ID, and no presigned URL is ever returned. An upload
token is 256 random bits bound to one asset, stored hashed and checked against the database on every
request; it ends at its expiry, at commit and at abort. tusd stores its upload object and its
`.info` and `.part` objects under the asset's source prefix (the tus resource ID clients see is the
asset ID), and Postgres advisory locks keep one writer per upload across edge replicas. tusd parks
incoming data on local disk until a part is complete, so edge needs temporary disk of about three
part sizes per active tus upload.

**What the upload path does not protect against.**

- A token holder can upload to that one asset until the token expires, is committed or is aborted.
  Tokens are not bound to an address or an origin.
- Uploads are not scanned for malware. The size limit (`CIPHERFRAME_MAX_SOURCE_BYTES`) and the token
  lifetime bound what a token holder can send; they are DoS mitigations, not guarantees. Duration and
  resolution limits are enforced by the probe step, not here.
- Abandoned uploads that nobody aborts leave incomplete multipart uploads until the storage purge or
  a bucket lifecycle rule removes them. An abort that races a tus chunk in flight can leave a partial
  object behind for the same purge.

## State

- Datastore: PostgreSQL (ADR 0007), described under [Datastore](#datastore). The job queue arrives
  with M1-5.
- Jobs use a language-neutral JSON envelope (`spec/jobs/`) so a non-Go worker can consume them
  (**pending P21** for the contract).

## Datastore

PostgreSQL is the only stateful dependency (ADR 0007). The minimum supported version is **16**
(ADR 0017): `db.CheckServerVersion` refuses older servers and servers whose version it cannot read.
CI runs the repository tests on 16 and 18.

| Table | Holds |
|---|---|
| `tenants` | The isolation boundary. `disabled_at` fails authentication closed. |
| `clients` | An embedding application or environment inside a tenant. |
| `api_keys` | Named, scoped credentials of a client: prefix, `HMAC-SHA256(pepper, secret)`, the pepper version, and an optional previous hash that stays valid for a rotation overlap window. |
| `assets` | Asset skeleton: owner tenant, creating client, lifecycle state. Later milestones add columns. |
| `audit_events` | Append-only record of who did what, in which tenant. |

- **Identifiers** are UUIDv7 values generated in Go (ADR 0011); no column has a database default id.
  Repositories convert between database UUIDs and the typed IDs of `internal/id` at the boundary.
- **Rotation** rewrites the secret on the same `api_keys` row (ADR 0009). The id, prefix, client and
  scopes never change, so assets and audit rows that point at the key or its client stay valid. The
  old hash moves to the `previous_*` columns; a CHECK constraint keeps those three columns all set or
  all null.
- **Audit rows have no foreign keys** on purpose. They must survive deletion of the tenant, client,
  key or asset they describe, and an insert must never fail or block because a parent row is gone.
  The cost is that nothing in the database stops an audit row naming a tenant that never existed;
  the application only writes IDs it has just authenticated.
- **Tenant isolation** is enforced in the queries: every tenant-scoped read takes the tenant ID and
  filters on it, so another tenant's row is reported as not found. This is application-level
  isolation, not Postgres row-level security.
- **Errors** are mapped at the repository boundary: no rows is `not_found`, a unique violation is
  `conflict`, connection loss and timeouts are `dependency_unavailable` and `timeout`, and anything
  unrecognised is `internal_error`. An unknown failure is never reported as `not_found`.
- **Migrations** are plain SQL files in `internal/db/migrations/`, embedded in the binary and applied
  by goose through `db.Migrate`, which then applies River's schema too (see [Jobs](#jobs)). The call
  is idempotent, and a Postgres advisory lock serialises instances that start together. `sqlc` reads the same files to generate the typed queries in
  `internal/db/dbgen`; CI runs `sqlc diff` to catch stale generated code.

**What the datastore does not protect against.** Anyone with access to the database, such as an
operator or a superuser, can read and change every row, including audit events. A leaked database
without the pepper does not reveal usable API keys (ADR 0009), but a leaked database together with
the pepper lets an attacker test candidate keys. Backups hold key hashes and, later, wrapped content
key material for as long as they exist; how backups are covered by deletion is described in the
deletion documentation, not here.

## Jobs

Background work runs on **River** (ADR 0007) behind Cipherframe's own interface in `internal/jobs`:
handlers register typed job kinds and never import River types. `db.Migrate` applies Cipherframe's
goose migrations and then River's schema (through River's migrator, pinned by the version in
`go.mod`, under its own advisory lock), so one call brings a database up to date.

- **Transactional enqueue.** `Queue.Enqueue(ctx, tx, args, opts)` inserts the job in the caller's
  transaction. If the transaction rolls back, no job exists; if it commits, the job runs. This is
  what lets a state change and the job that must follow it succeed or fail together.
- **Retry policy.** Each kind has its own attempt limit (default 5, counting the first run) and
  backoff (default: 15 seconds doubling to a 30 minute cap). A handler that returns an `*errs.Error`
  whose registered code means the work can never succeed (for example `invalid_request`, `not_found`,
  `forbidden`, `conflict`) has its job **cancelled at once**. A retryable code, `internal_error`
  (usually an unclassified, possibly transient failure), an unregistered code and any other error
  retry with backoff until the limit, then the job is **discarded**. A panic is retried as an internal error. `jobs.Snooze` waits without using an
  attempt.
- **Dead-letter list.** Cancelled and discarded jobs are the dead letters. `Queue.ListDead` pages
  through them newest first and shows the kind, state, attempts, timestamps and the **last error
  code only**; `Queue.RetryDead` puts one back in the queue. No arguments and no error text are
  returned, and River is only ever given a fixed text holding the error code, so a handler's error
  (which could quote a signed URL or an object key) is never stored in the job's error history.
- **Hand-off to external workers** (ADR 0010). River cannot be worked from Python, so work for a
  non-Go worker goes through the `external_tasks` table. `Queue.CreateTask` writes a row holding a
  versioned JSON envelope and a River "await" job in the same transaction. An external worker claims
  rows with `FOR UPDATE SKIP LOCKED`, keeps a lease alive by heartbeat and writes a result; the
  protocol, with the exact SQL, is in [`spec/jobs/README.md`](../spec/jobs/README.md) and the
  envelope and result are JSON Schemas (`spec/jobs/*.schema.json`) with test vectors that both the Go
  side and any worker must pass. The await job snoozes while the task is pending or leased; when the
  task succeeded it hands the parsed result, including the derived artifacts the Go side must
  register (invariant I6), to a callback; a retryable failure puts the task back to pending with the
  attempt number plus one until `max_attempts`; a non-retryable failure, or an exhausted one, cancels
  the await job into the dead-letter list. A lease that expires is reclaimable by another worker,
  and each reclaim counts as an attempt, so a task that keeps crashing its workers ends as a
  `lease_expired` failure instead of looping. Only the lease holder can heartbeat, complete or fail a
  task. A stored result that does not follow the contract is never acted on: the await job is
  cancelled with the code `invalid_result`.

**What the job system does not protect against.**

- Delivery is **at-least-once**. A job can run again after a crash, a timeout or a lost database
  connection, and the result callback of an external task can run more than once. Handlers and
  callbacks must be idempotent.
- An external worker with database access to its table **can read every task envelope** of the kinds
  it claims and can write any task's result. The dedicated database role in `spec/jobs/README.md`
  keeps it away from every other table, but it is a boundary around the worker, not between tenants.
  Envelopes carry identifiers and parameters only: never secrets, tokens, signed URLs or source object
  keys.
- Whoever can read the database can read job arguments (River stores them as JSON), so arguments must
  not hold secrets either.
- Retrying a dead external task from the dead-letter list is not supported when its task failed
  non-retryably or has run out of attempts; the await job would cancel it again at once. Create a new task instead.
- The await job polls on River's scheduling interval (a few seconds), so a result is acted on with
  that much delay.

## Media toolkit

Package `internal/media` is the worker's interface to FFmpeg and FFprobe (ADR 0024, ADR 0025). Both
run only as separate processes started by `exec.CommandContext` with an argument array: no shell, no
cgo, no libav (invariant I1). The child gets an empty environment, so the worker's secrets never reach
it. A source path is handed over as an absolute `file:` URL with `-protocol_whitelist file,pipe`, so a
hostile file name can be neither an option nor a URL.

- **`Tools.CheckCapabilities`** runs at startup in the worker role only (api and edge need no
  FFmpeg). It lists the build's encoders, decoders, muxers, demuxers, protocols and filters and fails
  with one message naming everything missing.
- **`Tools.Probe`** runs `ffprobe -print_format json -show_format -show_streams` with a timeout and a
  4 MiB output cap and returns `Info`: container, duration, the first non-cover-art video stream and
  the first audio stream. The video's *display* size applies the sample aspect ratio and the display
  matrix rotation (90 and 270 degrees swap width and height; other angles are refused).
- **`Validate(Info, Limits)`** rejects a missing video stream, unsupported containers and codecs,
  absurd or zero dimensions, and sources over the duration or resolution limits. Errors are
  `invalid_request` with a fixed detail that names the problem and the limit, never a path.
  Resolution limits apply in either orientation to both the stored frame and the display size.
- **`Tools.Transcode`** runs the one FFmpeg process of the processing pipeline (below) and parses
  its `-progress` output.
- **`Ladder(Info)`** picks the renditions: 1080, 720, 480, 360 and 240 by display height, a rung only
  if the source is at least that tall (nothing is upscaled), at least one rung always (a shorter
  source keeps its own height rounded down to even), widths from the display aspect ratio rounded to
  even, CRF 23, maxrate caps of 4500, 2500, 1200, 700 and 350 kbps with a buffer of twice the cap, and
  AAC 96 kbps when the source has audio. The ladder does not look at the source bitrate.

`internal/media/testmedia` generates fixtures at test time with a test-only FFmpeg that has the lavfi
sources; the production FFmpeg stays minimal. No binary fixtures are committed.

The worker image (`build/worker.Dockerfile`) is separate from the api and edge image (ADR 0008).

### What the media toolkit does not protect against

- FFmpeg parses untrusted input. Probing and the minimal build reduce what a hostile file can reach
  but do not make parsing safe; isolate the worker (least privilege, resource limits, no network
  beyond what it needs).
- Probe results describe what a file claims. Validation bounds the claims; it cannot bound the work
  a decoder does on a crafted stream, which is why a transcode timeout exists.

## Processing pipeline

`asset.process` (package `internal/pipeline`, registered in the worker role only) takes a `committed`
asset to `ready` (ADR 0024). Job arguments are the tenant and asset IDs and nothing else.

The job runs on its own River queue, `media`, apart from the default queue that carries `kms.rewrap`. A worker
process works `CIPHERFRAME_WORKER_MEDIA_CONCURRENCY` media jobs at once (default 1, because one FFmpeg run
already uses every core) and 10 default-queue jobs; the api role inserts into `media` directly.

1. **Claim.** Compare-and-set `committed -> processing`. A retried job finds the asset already
   `processing` and carries on; an asset that is `ready`, `failed` or `deleted` needs no work and the
   job ends successfully.
2. **Start clean.** Every HLS object under `t/<tenant>/a/<asset>/hls/` in the delivery bucket and every
   HLS row in `asset_artifacts` left by an earlier attempt is removed (the prefix comes from
   `storage/keys`, so objects an attempt uploaded but never registered go too). The content key is
   kept. This is what makes the job idempotent.
3. **Download and hash in one pass.** The source is streamed from the source bucket into the job's
   private directory under `CIPHERFRAME_WORK_DIR` (mode 0700, removed when the job ends, whatever the
   outcome) through an `io.TeeReader` into SHA-256: bounded memory, no second read. `source_sha256`
   and `source_size_bytes` are stored on the asset. A size that differs from the declared
   `size_bytes` fails the asset (`source_mismatch`); a body that ends early is a retryable error.
4. **Probe, validate, ladder** (media toolkit above). A file that is not an acceptable video fails
   the asset with `invalid_media`.
5. **Content key.** Created once, here, before any rendition work, in a transaction that holds the
   asset row lock; a retry finds and reuses it. It is never created lazily inside per-rendition work.
6. **Transcode.** One FFmpeg process decodes the source once, splits the frames into one scaled
   branch per rendition and encodes them all (below). A decoder failure fails the asset
   (`transcode_failed`), exceeding `CIPHERFRAME_TRANSCODE_TIMEOUT` fails it too (`transcode_timeout`).
   Progress (`out_time_us`) is throttled into the asset's `progress` column (0 to 90 while encoding,
   99 after the upload, 100 when ready; a hint for clients).
7. **Encrypt and upload.** For each rendition, each media segment is read, encrypted in memory with
   AES-128-CBC under a fresh random IV (package `internal/hls`, [encryption.md](encryption.md)),
   hashed as stored, and uploaded; the plaintext file is deleted as soon as it is read and the
   plaintext buffer cleared. The init segment is uploaded as FFmpeg wrote it.
8. **Playlists.** Go writes the canonical playlists, never FFmpeg's: per rendition a VOD media
   playlist (`EXT-X-MAP`, then for every segment an `EXT-X-KEY:METHOD=AES-128,URI="cipherframe-key",IV=0x...`
   and `EXTINF`), and a master playlist with `BANDWIDTH` (peak segment bitrate, never below the
   average; a final segment shorter than half the target is left out of the peak), `AVERAGE-BANDWIDTH`,
   `RESOLUTION`, `CODECS` (read from the avcC and esds boxes of each init segment) and `FRAME-RATE`,
   lowest bandwidth first. `cipherframe-key` is a placeholder: stored playlists never contain a
   token, a session or a key URL; the edge rewrites the key URI per playback session (see
   [Playback delivery on edge](#playback-delivery-on-edge)).
9. **Register and finish.** Every object written to the delivery bucket is recorded in
   `asset_artifacts` (asset, kind `master|playlist|init|segment|poster`, bucket role, object key,
   size, SHA-256 of the stored bytes: invariant I6, the start of the derived-artifact registry for
   M6-1) and the asset moves `processing -> ready` with its duration and a JSON summary of the
   renditions, in one transaction.

Object keys are `hls/master.m3u8` and, per rendition, `hls/<name>/playlist.m3u8`, `init.mp4` and
`seg-<n>.m4s` (n from 0), under `t/<tenant>/a/<asset>/`.

**The FFmpeg invocation** (one process, argument array, empty environment, `file:` paths, protocols
limited to `file,pipe`; `TranscodeArgs` in `internal/media/transcode.go`):

```
ffmpeg -hide_banner -nostdin -v error -nostats -progress pipe:1 -protocol_whitelist file,pipe -y
  -i file:SRC
  -filter_complex "[0:V]fps=R,split=N[s0]..[sN-1];[s0]scale=W0:H0:flags=bicubic,setsar=1,format=yuv420p[v0];..."
  # per rendition i:
  -map [vi] [-map 0:A]
  -c:v libx264 -profile:v high -preset medium -crf 23 -maxrate Mk -bufsize 2Mk
  -g G -keyint_min G -sc_threshold 0 -x264-params open-gop=0 -forced-idr 1
  -force_key_frames expr:gte(t,n_forced*2) -fps_mode cfr
  -c:a aac -b:a 96k -ac 2 -ar 48000
  -f hls -hls_time 6 -hls_playlist_type vod -hls_segment_type fmp4 -hls_flags independent_segments
  -hls_list_size 0 -start_number 1 -hls_fmp4_init_filename init.mp4
  -hls_segment_filename file:OUT/<name>/seg_%d.m4s  file:OUT/<name>/playlist.m3u8
```

`R` is the source frame rate capped at 60 (NTSC rates stay exact rationals), so every rendition has the
same constant frame rate; `G` is two seconds of frames. Rotation needs no argument: FFmpeg applies the
display matrix when it decodes, and every rendition is scaled to square pixels at the rotated size.

**Keyframe alignment (pitfall 4).** All renditions see the same frames at the same constant frame
rate. Each encoder is forced to a keyframe on the first frame at or after every multiple of two seconds
(`-force_key_frames`), cannot add scene-cut keyframes (`-sc_threshold 0`, `-keyint_min` equal to
`-g`), and writes IDR frames with closed GOPs. The HLS muxer cuts a segment at the first keyframe after
six seconds, which is the same frame in every rendition, so segment *n* starts at the same timestamp
everywhere. After the run Go checks that every rendition has the same number of segments of the same
durations (`CheckAligned`); the integration test additionally decrypts each segment and reads its
start timestamp with FFprobe.

**Failure handling.** A file that cannot be processed fails the asset with a stable code in
`failure_code` (`invalid_media`, `transcode_failed`, `transcode_timeout`, `source_mismatch`,
`source_missing`) and the job is cancelled (not retried); partial output is removed. A storage,
database or key-provider outage is retried with the job's backoff; if the last attempt also fails the
asset becomes `failed` with `processing_failed`. Shutdown or the job's own deadline interrupts the job
without failing the asset; the next attempt starts clean. If the asset leaves `processing` while the
job runs (it was deleted), the job removes what it uploaded and ends.

### What the processing pipeline does not protect against

- **Plaintext exists on the worker's disk while a job runs.** FFmpeg's HLS muxer writes unencrypted
  segments (and the downloaded source) into the job directory; they are deleted when the job ends and
  each segment is deleted as soon as it has been encrypted, but a crash that kills the worker process
  (`SIGKILL`, out of memory, a lost node) can leave a `job-*` directory behind. Use a dedicated,
  private (ideally encrypted or ephemeral) volume for `CIPHERFRAME_WORK_DIR` and clean it on start.
  This refines ADR 0024, which said plaintext segments never touch disk.
- The content key is in worker memory while a job runs (as on every key read) and is cleared after
  use on a best-effort basis; a memory dump of the worker can expose it.
- The init segment is stored unencrypted (see [encryption.md](encryption.md)).
- The source file in the source bucket is not encrypted by this pipeline; it stays until deletion.
- Segment hashes in `asset_artifacts` prove what was stored at upload time; they are not signed.
- A source file is hostile input to a C media decoder. See the media toolkit section above.

## Playback delivery on edge

The edge role serves a playback session's playlists, segments and content key (ADR 0027, 0028, 0030).
The routes and their rules are in
[api.md](api.md#playlists-and-segments-on-edge-adr-0027-0030); this section is how they fit together.

```
player -- GET master.m3u8 / media.m3u8 -->  guard --> storage.Get(playlist) --> hls.Rewrite* --> player
player -- GET init.mp4 / seg-N.m4s     -->  guard --> storage.Get(segment)  --> io.Copy       --> player
```

- **Guard** (`internal/edge/play_guard.go`): path allowlist, token from the header (or `t` when the
  tenant allows it), `Keyring.Open` (MAC, expiry, scope), the token's session equal to the path's,
  then the tenant's settings for `token_in_url` and CORS. Playlists add the stateful session check.
- **The token carries the tenant.** Claims hold session, asset and tenant, so a segment's object key
  (`t/<tenant>/a/<asset>/hls/<rendition>/seg-N.m4s`, built by `internal/storage/keys`) comes from the
  authenticated claims alone and a segment request needs no database round trip. The alternative
  (a lookup of asset, then tenant) would put a query on the hottest path.
- **Settings and the session's tenant are cached in process** (`play_cache.go`): 30 seconds, bounded
  (1024 tenants, 4096 sessions), only successful lookups stored (plus "no such session"). The
  steady-state cost of a segment is zero queries. A CORS preflight has no token, so it finds the tenant
  from the session in the path through the second cache; the session-to-tenant mapping never changes.
- **Delivery strategy** (ADR 0032): with the tenant setting `delivery = presigned`, the media-playlist
  handler passes `hls.RewriteMediaWith` a mapping from `init.mp4` / `seg-N.m4s` to the delivery
  bucket's presigned GET URL for the key built by `internal/storage/keys`. The lifetime is
  `min(token expiry - now, 10 minutes)` in whole seconds (so a URL never outlives its token), and a
  token with under a second left is refused as unauthorized. The setting comes from the same 30
  second cache as `token_in_url`. Signing is local (no storage call), URLs are never logged, and
  `proxy` output is byte-identical to before.
- **Rewriting** (`internal/hls/rewrite.go`) is a strict line rewriter, not a general parser: it accepts
  exactly what the pipeline writes and refuses the rest. Stored playlists never change, and everything
  session-specific (the key URI, the optional token) is added on the way out.
- **Segments are streamed**: `storage.Get` returns a reader and the response is an `io.Copy` of it
  with `Content-Length` from the object's size, so memory use does not depend on segment size, and a
  client that hangs up stops the read and closes the object.
- **The key endpoint** (`internal/edge/play_key.go`) runs the guard with scope `key`, which always reads
  the session row (never cached), then checks the asset is `ready`, then the two Postgres-backed
  bounds, then unwraps the content key through `internal/contentkey`. The per-token bound is one
  `INSERT ... ON CONFLICT DO UPDATE ... WHERE fetches < limit RETURNING` statement taken *before* the
  key service is called and given back if no key comes out: counting afterwards could be exceeded by
  every request already in flight, and a count never given back would let an outage eat a viewer's
  fetches. The per-minute window is two columns on the session row, updated in one statement. No
  per-request state is kept in process, so the bounds are exact across replicas. Anomaly events go to
  `playback_events`; the per-token counter table is swept by a periodic task in the edge role
  (`playback.RunSweeper`). The key is read into a 16-byte buffer that is cleared after the
  response is written.
- **Session lifecycle** (`internal/edge/play_lifecycle.go`): heartbeat and end run the same guard
  without its session-row read, because each enforces the session's state inside the one statement
  that changes it. The heartbeat is a single `UPDATE ... WHERE state = 'active' AND expires_at > now AND
  last_heartbeat_at > now - idle AND last_heartbeat_at <= now - gap RETURNING *`: "usable", "not idle"
  (judged on the previous heartbeat) and "not too frequent" cannot be separated by a concurrent request,
  and a script cannot mint tokens faster than one per gap. When it returns no row, one read tells
  "too soon" (429) from "unusable" (401). Edge signs the tokens it returns. That adds no exposure: the
  symmetric HMAC key is already in the edge role to verify every token (ADR 0028), and a compromised
  edge process could already forge tokens. Revocation (api role, `internal/playback/lifecycle.go`) is an
  `UPDATE ... WHERE state = 'active'` on the row the guard reads on every playlist, key and heartbeat
  request, which is why it applies at once there and not to segments, which never read the row.
- **The expiry sweep** (`playback.RunSweeper`, edge role) ends active sessions past `expires_at` or idle
  past their tenant's idle timeout, 1000 per statement (`FOR UPDATE SKIP LOCKED`, so replicas do not
  wait for each other), over two partial indexes on active rows. It is housekeeping: no check depends on
  it.
- **The edge role holds KMS access.** The key endpoint needs the same key service as the worker, so an
  edge process builds the KMS provider and the content key manager at start-up and refuses to start
  when its configuration is missing or wrong (the check every role runs). An attacker who compromises
  an edge process can unwrap the content keys of assets while they are played, and can read the
  playback token signing keys; this is inherent to AES-128 HLS, where the player must receive the key
  (I8, see [threat-model.md](threat-model.md)).
- **Failure mapping** follows the storage port: a missing object is `404`, an outage `503`, a timeout
  `504`, refused credentials `500` (invariant I11: an outage is never reported as "not found"). The same holds for the key endpoint:
  a key service or database outage is `503`, never `401` or `404`.

## Keys

Each asset has one active content key (I7), wrapped by a key-encryption key held in a key management
provider (AWS KMS, Vault Transit, GCP KMS; a development-only local provider is **pending P5**). See
[encryption.md](encryption.md).

## Lifecycle

`created → uploading → committed → processing → ready | failed → deleted`

Every change is a compare-and-set in the database (`UPDATE … WHERE state = $expected`) along the
edges of one Go table, so two writers can never both win a transition (ADR 0026). Commit enqueues
`asset.process` in the same transaction that sets `committed`; the worker role handles it (see
[the processing pipeline](#processing-pipeline)).

Deletion enumerates storage, destroys the content key, re-lists to confirm nothing is left, and signs
a record. See [integrity.md](integrity.md).

## What this architecture does not protect against

See [threat-model.md](threat-model.md#out-of-scope). In short: screen capture, authorized viewers
keeping copies, scripted reassembly during a valid session, and compromise of the operator's own
storage or KMS credentials.
