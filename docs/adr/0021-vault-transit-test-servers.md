# 0021. Vault Transit test servers

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M2-2)
- Deciders: project owner

## Context

D3 names HashiCorp Vault Transit as a production provider. Its integration tests need a Transit
server. HashiCorp Vault has been licensed under BUSL-1.1 since 2023; OpenBao is an MPL-2.0 fork with
the same Transit API.

## Options considered

1. **OpenBao only** in CI.
2. **HashiCorp Vault only** in CI.
3. **Both** in CI.

## Decision

Option 3. The Transit provider's integration suite runs against both a HashiCorp Vault dev server and
an OpenBao dev server, each pinned by tag and digest, as two CI matrix entries. The provider is
documented as supporting both.

## Consequences

- Strongest evidence that the provider works with either server.
- CI takes slightly longer, and the project runs a BUSL-licensed image in CI. Running Vault's dev
  server for testing is permitted by its licence; Cipherframe does not distribute Vault.
- If either server's Transit API diverges in future, the failing matrix entry shows it immediately.
