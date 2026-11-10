# Encryption

> Status: skeleton (M0-4). Details land with M2 (key management) and M3 (packaging).

## Layers

1. **Segments**: HLS AES-128 with explicit per-segment IVs, under one content key per asset (I7).
2. **Content key at rest**: envelope-encrypted with an AEAD, bound to the asset id and key id as
   associated data, wrapped by a key-encryption key (KEK).
3. **KEK**: held by a key management provider. Every wrapped key records provider, key id and
   version.

| Provider | Status |
|---|---|
| AWS KMS | planned (M2) |
| HashiCorp Vault Transit | planned (M2) |
| GCP KMS | planned (M2) |
| Local development provider | pending P5; development only |

## Operations

- **Re-wrap** (M2-4): re-wraps content keys under a new KEK version without re-encrypting media.
- **Re-key** (M10-4, optional): re-encrypts an asset's segments under a new content key and destroys
  the old one.
- **Crypto-shredding** (M6): destroying the content key row makes every copy of the ciphertext
  unreadable.

## Failure behaviour

If the key provider is unavailable, key requests fail closed with a clear error and no key material
in logs (I11).

## What this does not protect against

- Standard HLS AES-128 is **not DRM**. A viewer with a valid session receives the content key, so the
  video can be recorded or reassembled during the session.
- Compromise of the operator's KMS credentials exposes every content key.
- Re-wrapping and re-keying do not help against plaintext already saved.
- Losing the KEK makes all assets permanently unreadable.
