# 0012. Error model

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-2)
- Deciders: project owner

## Context

Clients, SDKs, workers and operators all need to tell errors apart reliably, know whether retrying
can help, and correlate a failure with server logs. Security failures must fail closed and never be
reported as success (I11).

## Options considered

1. **RFC 9457 problem details** with extension fields.
2. **A custom JSON envelope**.

## Decision

Option 1.

- Error responses use `Content-Type: application/problem+json` with the standard members `type`,
  `title`, `status` and `detail`, plus extensions `code`, `retryable` and `request_id`.
- `type` is `urn:cipherframe:error:<code>` (the project owns no domain to publish error pages on).
- `code` is `lower_snake_case`, taken from a single closed registry in Go code. Call sites cannot
  invent codes. The registry is also published as an enum in `spec/openapi.yaml`, so the spec, the
  server and the SDKs agree.
- `retryable` says whether repeating the same request may succeed. The worker uses the same flag to
  decide between retrying a job and dead-lettering it.
- Every request gets a UUIDv7 request ID, returned in `X-Request-Id` and in error bodies, and attached
  to every log line for that request.
- `detail` never contains secrets, tokens, signed URLs, source object keys or internal error text.
  Unexpected errors are logged with their cause and returned as a generic `internal_error`.

## Consequences

- Adding a code is a compatible change; renaming or removing one is breaking.
- Generic HTTP tooling understands the body without Cipherframe-specific code.
- Errors from dependencies (storage, KMS, database) are mapped explicitly; an unmapped error is never
  reported as "not found" or "tampered" (pitfall 2).
