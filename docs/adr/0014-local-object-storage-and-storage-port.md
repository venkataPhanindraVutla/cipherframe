# 0014. Local object storage and the storage port

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-3, M1-8)
- Deciders: project owner

## Context

The build plan names MinIO for local development (M1-8) and for the storage conformance suite (M1-3).
As of 2026-11-10 the MinIO repository is archived and its last release is from 2025-10, so it receives
no security fixes. Cipherframe needs an S3-compatible store that runs without a cloud account.

Separately, a presigned URL's signature covers the host, so URLs signed against an internal address
(a Compose service name) cannot be used by a browser.

## Options considered

1. **SeaweedFS** (Apache-2.0, actively released, mature S3 gateway).
2. **RustFS** (Apache-2.0, active, younger).
3. **The last MinIO release**, pinned.
4. **SeaweedFS and RustFS both** in CI.

## Decision

- **SeaweedFS** replaces MinIO in Docker Compose and in the storage conformance suite. Wherever the
  build plan says "MinIO" for local development or tests, read "SeaweedFS". An opt-in CI job runs the
  same suite against real S3 and R2 when credentials are provided.
- Compose pins a SeaweedFS release. On every start an init step creates the source and delivery
  buckets and reapplies a private policy, so a public bucket cannot persist.
- The storage port has two S3 clients: an **internal** client for server-side calls and a **public**
  client that signs URLs against the externally reachable endpoint (`CIPHERFRAME_S3_PUBLIC_ENDPOINT`).
- Batch deletes inspect the per-key errors S3 returns inside a successful response; any failed key
  fails the call.
- Every object key is built by one key-layout module, and deletion prefixes come from the same module,
  so they cannot drift apart.

## Consequences

- No cloud account is needed for development or CI.
- SeaweedFS differs from AWS S3 in places; the conformance suite and the opt-in real-S3 job are what
  prove compatibility, not the choice of emulator.
- If SeaweedFS stops fitting, swapping the local store only touches Compose and CI, not the service.
