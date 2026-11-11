# Architecture Decision Records

Process: [0001](0001-record-architecture-decisions.md). New records start from [`template.md`](template.md).

## Decision log

| ADR | Title | Gate | Status | Date |
|---|---|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | none | Accepted | 2026-11-10 |
| [0002](0002-confirmed-baseline-decisions.md) | Confirmed baseline decisions | D1 to D10 | Accepted | 2026-11-10 |
| [0003](0003-repository-owner-and-module-path.md) | Repository owner and Go module path | P1 | Accepted | 2026-11-10 |
| [0004](0004-go-toolchain-bundle.md) | Go toolchain bundle | P3 | Accepted | 2026-11-10 |
| [0005](0005-ci-release-signing-and-sbom.md) | CI platform, release signing and SBOM | P15 | Accepted | 2026-11-10 |
| [0006](0006-repository-layout-and-project-policies.md) | Repository layout and project policies | none | Accepted | 2026-11-10 |
| [0007](0007-datastore-job-queue-and-migrations.md) | Datastore, job queue and migrations | P2 | Accepted | 2026-11-10 |
| [0008](0008-service-topology.md) | Service topology | P4 | Accepted | 2026-11-10 |
| [0009](0009-tenancy-and-api-keys.md) | Tenancy and API keys | P7 (API keys) | Accepted | 2026-11-10 |
| [0010](0010-language-neutral-job-contract.md) | Language-neutral job contract | P21 (contract) | Accepted | 2026-11-10 |
| [0011](0011-id-scheme.md) | ID scheme | none | Accepted | 2026-11-10 |
| [0012](0012-error-model.md) | Error model | none | Accepted | 2026-11-10 |
| [0013](0013-configuration.md) | Configuration | none | Accepted | 2026-11-10 |
| [0014](0014-local-object-storage-and-storage-port.md) | Local object storage and the storage port | none | Accepted | 2026-11-10 |
| [0015](0015-api-conventions-and-contract-test.md) | API conventions and contract test | none | Accepted | 2026-11-10 |
| [0016](0016-api-key-pepper-versioning.md) | API-key pepper versioning | none | Accepted | 2026-11-10 |
| [0017](0017-postgres-version-support.md) | Postgres version support | none | Accepted | 2026-11-10 |
| [0018](0018-management-api-for-clients-and-keys.md) | Management API for clients and keys | none | Accepted (flagged for owner review before v1.0.0) | 2026-11-11 |
| [0019](0019-local-development-key-provider.md) | Local development key provider | P5 | Accepted | 2026-11-11 |
| [0020](0020-envelope-encryption-aead.md) | Envelope encryption AEAD | none | Accepted | 2026-11-11 |
| [0021](0021-vault-transit-test-servers.md) | Vault Transit test servers | none | Accepted | 2026-11-11 |
| [0022](0022-key-provider-packaging.md) | Key provider packaging | none | Accepted | 2026-11-11 |
| [0023](0023-kms-provider-test-strategy.md) | KMS provider test strategy | none | Accepted | 2026-11-11 |

## Open gates

P6, P7 (JWT and signed callback), P8 to P14, P16 to P20, P21 (worker). See the build plan's
decision register.
