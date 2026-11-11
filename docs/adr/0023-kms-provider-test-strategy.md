# 0023. KMS provider test strategy

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M2-2)
- Deciders: project owner

## Context

M2's acceptance asks for an integration test per provider: "LocalStack, Vault dev server, a GCP
emulator or documented manual verification if no emulator exists". As of 2026-11-11 LocalStack's
open-source repository is archived (2026-03) and its images moved to a calendar-versioned, likely
token-gated track. Google provides no Cloud KMS emulator.

## Options considered

AWS: moto server; LocalStack; real AWS only.
GCP: an in-process fake server plus an opt-in real run; an opt-in real run only.

## Decision

| Provider | Normal CI | Opt-in CI (when credentials are configured) |
|---|---|---|
| Local | Unit and integration tests | n/a |
| Vault Transit | HashiCorp Vault and OpenBao dev servers (ADR 0021) | n/a |
| AWS KMS | **moto** server (Apache-2.0) via testcontainers, pinned by tag and digest | Real AWS KMS test key |
| GCP KMS | **In-process fake gRPC server** implementing the methods the provider uses, with key versions and error injection | Real Cloud KMS test key |

Every provider also runs the same provider conformance suite (wrap, unwrap, mixed key versions,
associated-data binding, outage behaviour). Manual verification steps for real AWS and GCP are
documented for operators.

## Consequences

- Every provider has automated coverage in normal CI without cloud accounts.
- Emulators and fakes can differ from the real services; the opt-in real-cloud jobs and the documented
  manual steps exist to catch that, and are expected to run before each release.
- This replaces LocalStack in the build plan's M2 acceptance criteria.
