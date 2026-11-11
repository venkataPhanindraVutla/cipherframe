# 0022. Key provider packaging

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M2-2)
- Deciders: project owner

## Context

M2-2 asks for the KMS providers to be "lazily loaded so the core carries no unused cloud SDK weight".
Go links everything at build time, so "lazy" has to mean compile-time selection. The GCP SDK in
particular brings a large gRPC and protobuf dependency tree.

## Options considered

1. **All in, opt-out build tags**: release builds include every provider; custom builds can drop one.
2. **Opt-in build tags**: the default build has only the local and Vault providers.
3. **Per-provider images**.

## Decision

Option 1.

- Each provider lives in its own package: `local`, `vault` (plain HTTP to the Transit API, no SDK),
  `awskms` and `gcpkms`. Only the provider registry imports them.
- The AWS and GCP providers are each guarded by an exclusion build tag (`nokms_aws`, `nokms_gcp`). A
  build with the tag does not link that SDK, and configuring the excluded provider fails at startup
  with a clear error.
- Release binaries and images are built without exclusion tags, so every provider is available.
- CI builds once with both exclusion tags to prove the core compiles without either SDK.

## Consequences

- Operators get every provider from the standard image with no build knowledge.
- The standard binary is larger (mostly the GCP gRPC stack). Size-sensitive deployments can build
  without the providers they do not use.
- Provider selection stays a configuration choice; nothing loads plugins at runtime.
