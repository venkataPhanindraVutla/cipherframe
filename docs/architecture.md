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
batch delete, presigned GET and PUT, and multipart upload with presigned parts. Bodies are streamed;
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
| source | `t/<tenant>/a/<asset>/source/original` |
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
  by goose through `db.Migrate`. The call is idempotent, and a Postgres advisory lock serialises
  instances that start together. `sqlc` reads the same files to generate the typed queries in
  `internal/db/dbgen`; CI runs `sqlc diff` to catch stale generated code.

**What the datastore does not protect against.** Anyone with access to the database, such as an
operator or a superuser, can read and change every row, including audit events. A leaked database
without the pepper does not reveal usable API keys (ADR 0009), but a leaked database together with
the pepper lets an attacker test candidate keys. Backups hold key hashes and, later, wrapped content
key material for as long as they exist; how backups are covered by deletion is described in the
deletion documentation, not here.

## Keys

Each asset has one active content key (I7), wrapped by a key-encryption key held in a key management
provider (AWS KMS, Vault Transit, GCP KMS; a development-only local provider is **pending P5**). See
[encryption.md](encryption.md).

## Lifecycle

`created → uploading → committed → processing → ready | failed → deleted`

Deletion enumerates storage, destroys the content key, re-lists to confirm nothing is left, and signs
a record. See [integrity.md](integrity.md).

## What this architecture does not protect against

See [threat-model.md](threat-model.md#out-of-scope). In short: screen capture, authorized viewers
keeping copies, scripted reassembly during a valid session, and compromise of the operator's own
storage or KMS credentials.
