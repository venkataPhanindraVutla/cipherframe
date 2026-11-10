# 0018. Management API for clients and keys

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M1-7)
- Deciders: implementer, flagged for owner review before v1.0.0

## Context

ADR 0009 fixes the tenancy model, the scopes, the key format and the rotation rule, and ADR 0016
the pepper versioning. M1-7 had to turn them into endpoints and a bootstrap path. The names and
rules below were not given by an owner decision, so they are recorded here and flagged for review
before the API is frozen at v1.0.0.

## Options considered

1. **Endpoints**: a small set under `/v1/` (below), or a full resource model with `PATCH`,
   `DELETE` and per-client sub-resources.
2. **Rotation rights**: admin only, or admin plus a key rotating itself.
3. **`last_used_at`**: written on every request, or throttled.

## Decision

**Endpoints** (api listener, all tenant-scoped to the caller's key):

| Operation | Scope |
|---|---|
| `GET /v1/whoami` | any valid key |
| `POST /v1/clients`, `GET /v1/clients` | `admin` |
| `POST /v1/keys`, `GET /v1/keys` | `admin` |
| `POST /v1/keys/{key_id}/rotate` | `admin`, or the key itself |
| `POST /v1/keys/{key_id}/revoke` | `admin` |

- Lists use keyset pagination on the creation-ordered ID: `limit` (1 to 100, default 50) and an
  opaque `cursor` (the last ID of the previous page); the response carries `next_cursor` while
  more items follow.
- A client or key of another tenant is `not_found`, never `forbidden`.
- Revocation is idempotent. Rotating a revoked key is `not_found`.
- Every create, rotate and revoke writes an audit row (action, target ID, request ID, actor client
  and key) in the same transaction as the change.

**Self-rotation.** A key without `admin` may rotate itself, so an integration can roll its own
credential without holding an admin key. It may not rotate any other key (`forbidden`).

**Default overlap.** The previous secret stays valid for `overlap_seconds` after rotation:
default 600 (ADR 0009), range 0 to 86400. 0 ends the old secret immediately.

**`last_used_at` throttling.** It is written at most once per minute per key: not when the stored
value is under a minute old, and not when this process already wrote it within the minute. It is a
hint for operators, not an audit record, so a failed write is logged and ignored.

**Authentication details.** `Authorization: Bearer cf_<prefix>_<secret>` (scheme
case-insensitive). Every failure, whatever its cause, is `401 unauthenticated` with one generic
detail and `WWW-Authenticate: Bearer`. A stored key whose pepper version is not configured is an
`internal_error`, and the server refuses to start in that state (ADR 0016). The HMAC is computed
over the 32 raw secret bytes. A lookup that finds no key still computes an HMAC, so timing does not
reveal which prefixes exist. Scopes are enforced from a Go table keyed by operationId that a test
compares with the `security` requirements in the spec.

**Bootstrap.** `cipherframe-server admin bootstrap --tenant-name N --client-name N` creates the
tenant, client and an all-scope admin key in one transaction, writes audit rows with no actor, and
prints only the key on stdout. `cipherframe-server admin pepper-usage` prints active key counts per
pepper version.

**Dependency.** Generated server code for operations with parameters or bodies imports
`github.com/oapi-codegen/runtime` (Apache-2.0), which brings `go-jsonmerge` and `nullable` (both
MIT). This is the first use of the runtime package; it is a build dependency of the generated code
and passes the licence policy.

## Consequences

- An integration can be given the least scopes it needs, and can roll its own key.
- A leaked key works until it is revoked or, after rotation, until its overlap ends.
- There is no endpoint to disable a client or tenant, to rename or delete clients, or to change a
  key's scopes; the first two exist only as database markers honoured by authentication. Add them
  when a milestone needs them.
- `last_used_at` can be up to a minute stale.
- Renaming an operation path or scope after v1.0.0 is breaking.
