# 0015. API conventions and contract test

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-6)
- Deciders: project owner

## Context

`spec/openapi.yaml` is the source of truth for the API, and CI must fail if the running API and the
spec diverge (M1-6). Orchestrators need separate liveness and readiness signals.

## Options considered

Paths: `/v1` with `/healthz` and `/readyz`, or unversioned paths with a single `/health`.

Contract test: a validator plus route coverage in Go, or the same plus spec-driven fuzzing.

## Decision

- API routes live under **`/v1/`**. A breaking change means `/v2/`, alongside `/v1/` for a
  documented period.
- **`/healthz`** reports that the process is alive and checks no dependencies.
- **`/readyz`** checks the database, object storage and job queue, returning 200 when all pass and
  503 with a per-check result list when any fails. It reveals no hostnames, credentials or error text.
- The **contract test** runs real requests against the server with a `kin-openapi` (MIT) validator
  that checks requests and responses against the spec. A coverage test asserts that every spec
  operation has a route and every route appears in the spec. Both run in the normal test job.

## Consequences

- Fuzzing from the spec is not included now; fuzz tests for token parsing and playlist rewriting
  arrive with M9-5.
- Health and readiness endpoints are unauthenticated and therefore return no sensitive detail.
