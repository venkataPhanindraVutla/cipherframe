# 0020. Envelope encryption AEAD

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M2-1)
- Deciders: project owner

## Context

M2-1 requires envelope encryption of each content key with an AEAD, binding the content key to the
asset id and key id as associated data. Cloud KMS providers wrap with their own algorithms; this
decision covers the AEAD Cipherframe itself uses (for example in the local provider of ADR 0019 and
for any data-key envelope the providers return).

## Options considered

1. **AES-256-GCM**: standard library, hardware-accelerated almost everywhere, FIPS-friendly.
2. **XChaCha20-Poly1305**: 192-bit nonces, fast without AES hardware, needs `golang.org/x/crypto`, not
   FIPS-approved.

## Decision

AES-256-GCM from the Go standard library, with 96-bit random nonces from `crypto/rand`.

- Associated data is a canonical, length-prefixed encoding of the asset id, the content key id, the
  provider name and the KEK version, so a wrapped key cannot be moved to another asset or key slot.
- The stored envelope carries a format version byte, so the scheme can change later without
  ambiguity.

## Consequences

- No new dependency.
- Random 96-bit nonces are safe here because each KEK version encrypts few messages (one per content
  key and per re-wrap), far below the collision bound. If a KEK ever had to encrypt billions of
  messages, this decision would need revisiting.
- This is not the segment cipher: HLS segments use AES-128 (CBC, per the HLS specification) under the
  content key, decided by the HLS standard rather than here.
