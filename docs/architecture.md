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
