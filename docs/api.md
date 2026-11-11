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
| Control plane | Embedding application servers | API keys; JWT and signed callback (M4-8, pending P7) |
| Data plane | Browsers | Short-lived playback tokens (pending P6) |
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
| `rate_limited` | 429 | yes | Too many requests; retry later. |
| `internal_error` | 500 | no | An unexpected server error. |
| `dependency_unavailable` | 503 | yes | A backing service (storage, database, key service) is unavailable. |
| `timeout` | 504 | yes | The operation did not finish in time. |

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
