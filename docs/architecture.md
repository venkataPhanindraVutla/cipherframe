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
Delivery}`, each a `Store`: put, get (optionally a byte range), head, list with a continuation cursor,
batch delete, presigned GET and PUT, and multipart upload (presigned parts for servers, and `UploadPart`,
which streams a part from a request body). Bodies are streamed;
library code never holds a whole object in memory. Creating buckets, ACLs, lifecycle rules and
versioning are not part of the port; they belong to deployment.

**Two clients.** An *internal* client (`CIPHERFRAME_S3_ENDPOINT`) makes every server-side call. A
*public* client (`CIPHERFRAME_S3_PUBLIC_ENDPOINT`, default the internal endpoint) is used only to sign
URLs, because a presigned URL's signature covers the host and a browser cannot use an internal
address. Credentials follow the three configuration states: a static key pair, the SDK default chain
(an empty variable), or anonymous (development only).

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

## Keys

Each asset has one active content key (I7), wrapped by a key-encryption key held in a key management
provider (AWS KMS, Vault Transit, GCP KMS; a development-only local provider is **pending P5**). See
[encryption.md](encryption.md).

## Lifecycle

`created → uploading → committed → processing → ready | failed → deleted`

Every change is a compare-and-set in the database (`UPDATE … WHERE state = $expected`) along the
edges of one Go table, so two writers can never both win a transition (ADR 0026). Commit enqueues
`asset.process` in the same transaction that sets `committed`; its handler arrives with M3-3.

Deletion enumerates storage, destroys the content key, re-lists to confirm nothing is left, and signs
a record. See [integrity.md](integrity.md).

## What this architecture does not protect against

See [threat-model.md](threat-model.md#out-of-scope). In short: screen capture, authorized viewers
keeping copies, scripted reassembly during a valid session, and compromise of the operator's own
storage or KMS credentials.
