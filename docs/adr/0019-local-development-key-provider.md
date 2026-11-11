# 0019. Local development key provider

- Status: Accepted
- Date: 2026-11-11
- Gate: P5
- Deciders: project owner

## Context

Content keys are envelope-encrypted under a key-encryption key (KEK) held by a key management provider
(D3: AWS KMS, Vault Transit, GCP KMS). The Docker Compose stack and the test suites must run without a
cloud account (v1 exit criterion 1).

## Options considered

1. **Built-in development provider**: a `local` provider in the binary with KEKs from a file or the
   environment.
2. **OpenBao dev server** in Compose, used through the real Vault provider.
3. **Both**: the built-in provider by default plus an optional OpenBao profile.

## Decision

Option 1.

- A `local` `KeyProvider` wraps content keys with AES-256-GCM (ADR 0020) under versioned KEKs read
  from configuration (`*_FILE` supported, ADR 0013). Every wrapped key records the provider (`local`),
  the key id and the KEK version, exactly like the production providers.
- It is labelled development-only everywhere it appears: in its name, in logs at startup, and in the
  docs. When `CIPHERFRAME_ENV=production` the process refuses to start with it.
- Docker Compose uses it with a `dev-placeholder-` KEK.

## Consequences

- No extra service in Compose; tests of envelope encryption, re-wrap and crypto-shredding run anywhere.
- The local provider holds KEKs in process memory and in configuration, which is exactly what the
  production providers avoid. That is why production refuses it.
- Exercising the Vault provider locally is still possible by pointing it at an OpenBao or Vault dev
  server (ADR 0021), outside Compose.
