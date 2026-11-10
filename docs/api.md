# API

> Status: skeleton (M0-4). The API is defined in M1-6.

## Source of truth

`spec/openapi.yaml` (OpenAPI 3.1) is the source of truth. Server interfaces are generated from it
(ADR 0004), and a contract test fails CI if the running API and the spec diverge.

## Surfaces

| Surface | Callers | Authentication |
|---|---|---|
| Control plane | Embedding application servers | API keys (M1-7); JWT and signed callback (M4-8, pending P7) |
| Data plane | Browsers | Short-lived playback tokens (pending P6) |
| Well-known keys | Anyone | None (public keys only) |

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

## What this does not protect against

- IDs are not secret. Knowing an object ID grants nothing by itself; access is decided by
  authentication and authorization, never by an ID being hard to guess. Only session IDs are
  secrets.
- UUIDv7 encodes the creation time to the millisecond, so object IDs reveal roughly when an object
  was created. Session IDs do not.
- The prefix check catches a wrong-type ID early; it is not an authorization check.
- `detail` is written to be safe to show, but callers should not parse it. `retryable` is advice:
  retrying a non-idempotent request can still cause duplicates unless an idempotency mechanism
  says otherwise.

- A leaked API key grants its client's full control-plane access until it is rotated.
- The control plane does not decide who may watch what; the embedding application does.
