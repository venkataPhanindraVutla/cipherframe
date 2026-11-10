# 0004. Go toolchain bundle

- Status: Accepted
- Date: 2026-11-10
- Gate: P3
- Deciders: project owner

## Context

The backend (API, edge, worker, CLI) is Go (D2). The plan makes `spec/openapi.yaml` the source of
truth for the API (M1-6), requires crypto-shredding where key rows are destroyed rather than flagged
(I5, I7), and requires secrets never to appear in logs (pitfall 9). The bundle should favour explicit
SQL, a generated contract, and few dependencies.

## Options considered

1. **Stdlib first, plus spec codegen**: `net/http` routing, server interfaces generated from the
   OpenAPI spec, plain SQL with generated typed queries.
2. **chi router with hand-written handlers**: more freedom; the spec is enforced only by the contract
   test, so drift is likelier.
3. **Web framework plus ORM (Echo/Gin + GORM)**: faster scaffolding; reflection-heavy and hides the SQL
   that deletion correctness depends on.

## Decision

Option 1:

| Concern | Choice |
|---|---|
| Go version | 1.27.x (`go 1.27` in `go.mod`, toolchain pinned in CI) |
| Router | `net/http` `ServeMux` with method and path patterns |
| API layer | `oapi-codegen` strict server generated from `spec/openapi.yaml` |
| Database | `pgx` v5 with `sqlc` (plain SQL, generated typed queries); assumes Postgres, confirmed at P2 |
| Migrations | Decided at P2 |
| Object storage | `aws-sdk-go-v2` S3 client (S3, R2, MinIO) |
| Config | Small typed loader: environment variables, `*_FILE` variants for secrets, validation, redacted printing |
| Logging | `log/slog` JSON output through a redacting handler |
| Tests | `testing`, `go-cmp`, `testcontainers-go` (MinIO, Postgres) |
| Lint and format | `golangci-lint` v2, `gofumpt`, `go vet`, `govulncheck` |

## Consequences

- Handler signatures follow the spec, so spec and code cannot silently diverge. The contract test
  (M1-6) still checks the running server.
- Exact library versions are pinned in `go.mod` when each is first used.
- If P2 picks a datastore other than Postgres, the `pgx`/`sqlc` rows are revisited in a superseding ADR.
- This ADR covers libraries only. Service topology is P4, observability exporters are P14.
