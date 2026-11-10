# 0017. Postgres version support

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-8; completes ADR 0007)
- Deciders: project owner

## Context

ADR 0007 makes Postgres the only stateful dependency and leaves the version to M1-8. Self-hosters
often run managed Postgres that lags the newest major release. On 2026-11-10 the current majors are
18.6, 17.11 and 16.15.

## Options considered

1. Compose on 18, support 16 and newer.
2. Compose on 18, support 18 only.
3. Compose on 17, support 15 and newer.

## Decision

Option 1.

- Docker Compose pins a Postgres 18 minor release.
- The minimum supported version is **Postgres 16**. The service checks the server version at startup
  and refuses to run below 16.
- CI runs repository and migration tests on both 16 and 18.
- Schema and queries avoid features newer than 16 unless a superseding ADR raises the minimum.

## Consequences

- Operators on managed Postgres 16 or 17 are supported.
- Raising the minimum later is a breaking change for those operators and is called out in release
  notes.
