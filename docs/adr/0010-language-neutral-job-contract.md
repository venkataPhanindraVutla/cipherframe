# 0010. Language-neutral job contract

- Status: Accepted
- Date: 2026-11-10
- Gate: P21 (contract; the Python worker itself is built in v2.1)
- Deciders: project owner

## Context

Go jobs run on River (ADR 0007). River jobs can be inserted from Python but not worked by it. The
v2.1 ML worker is Python and must consume work through a contract that does not depend on River's
internals.

## Options considered

1. **Hand-off table**: a River job writes a versioned JSON envelope to a Cipherframe table; Python
   claims it there.
2. **HTTP service**: a River job calls the Python worker over HTTP with the envelope.
3. **Python implements River's protocol**: couples us to River's internal schema.

## Decision

Option 1.

- **Envelope**: a versioned JSON document defined by a JSON Schema in `spec/jobs/`. It carries at
  least the envelope version, task id, kind, tenant id, asset id, attempt number, creation time, a
  kind-specific payload, and trace context. It never carries secrets or source object keys
  (pitfall 9).
- **Hand-off table** (`external_tasks`): written by a Go River job in the same transaction that
  records the step. External workers claim rows with `FOR UPDATE SKIP LOCKED`, hold a lease they
  extend by heartbeat, and write back a result envelope or an error with a retryable flag.
- **Resumption**: the waiting River job completes when the task result arrives, or retries or
  fails according to the result; expired leases are reclaimed.
- **Conformance**: the schema plus sample envelopes in `spec/jobs/` are test vectors; both the Go
  side and any external worker validate against them.
- In M1, only the schema, the table, the Go side and its tests are built. No Python code is written
  until v2.1.

## Consequences

- External workers need Postgres access scoped to the hand-off table (a dedicated database role),
  plus storage access for their inputs and outputs.
- The contract survives River upgrades because it never touches River's tables.
- Anything an external worker produces must still be registered as a derived artifact (I6); the
  result envelope reports it and the Go side registers it.
