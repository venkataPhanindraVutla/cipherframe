# Encryption

> Status: M2-1 and M2-3 implemented (key-provider interface, envelope encryption, content keys,
> local development provider). The cloud providers land with M2-2, re-wrap with M2-4 and packaging
> with M3.

## Layers

1. **Segments**: HLS AES-128 with explicit per-segment IVs, under one content key per asset (I7).
2. **Content key at rest**: envelope-encrypted with an AEAD, bound to the asset id and key id as
   associated data, wrapped by a key-encryption key (KEK).
3. **KEK**: held by a key management provider. Every wrapped key records provider, key id and
   version.

| Provider | Status |
|---|---|
| AWS KMS | planned (M2-2) |
| HashiCorp Vault Transit | planned (M2-2) |
| GCP Cloud KMS (`gcpkms`) | implemented |
| Local development provider (`local`) | implemented; **development only** (ADR 0019) |

## Key providers

A provider (`internal/kms`) wraps and unwraps keys under a KEK it holds:

- `Current` names the KEK (key id and version) that new wraps use.
- `Wrap(plaintext, aad)` returns the wrapped bytes plus the provider name, KEK key id and KEK version
  that made them. Empty plaintext and empty associated data are rejected.
- `Unwrap(wrapped, aad)` decrypts with the version the wrapped key names, so keys wrapped before a
  rotation stay readable.

A registry holds the provider for new wraps and every configured provider for unwrapping, looked up by
the provider name stored with each key. A key whose provider is not configured fails to unwrap with an
error; it is never skipped.

Provider failures are typed and mapped to API errors:

| Kind | Meaning | API error |
|---|---|---|
| `ErrUnavailable` | outage or timeout | `dependency_unavailable` (retryable) |
| `ErrDenied` | the provider refused our credentials | `internal_error` |
| `ErrInvalid` | authentication failed: tampered ciphertext, wrong associated data | `internal_error`, logged as an integrity failure |
| `ErrNotConfigured` | the provider or KEK version that wrapped the key is not available | `internal_error` |
| anything else | unknown | `internal_error` (never reported as tampering or as success) |

Errors and logs carry identifiers (asset id, content key id, provider, KEK id and version), never
keys, plaintext, ciphertext or associated data. Every provider must pass the shared conformance suite
in `internal/kms/kmstest` (round trip, associated-data binding, tamper detection, input validation,
mixed versions, outage behaviour; ADR 0023).

## GCP Cloud KMS provider

`CIPHERFRAME_KMS_PROVIDER=gcpkms` wraps content keys with Cloud KMS symmetric `Encrypt` and `Decrypt`
on one crypto key (`CIPHERFRAME_KMS_GCP_KEY_NAME`; see `docs/usage.md` for all settings).

- **Current KEK**: `GetCryptoKey` returns the primary version. The key must have purpose
  `ENCRYPT_DECRYPT` and an enabled primary, otherwise the provider reports `not_configured`. The KEK id
  is the crypto key name and the KEK version is the version number (for example `3`).
- **Wrap**: `Encrypt` on the crypto key, which uses the primary version. The envelope's associated
  data goes in as Cloud KMS additional authenticated data. The version that made the ciphertext is
  parsed from the response `name` (`.../cryptoKeyVersions/N`).
- **Unwrap**: `Decrypt` on the crypto key with the same associated data. Cloud KMS reads the version
  from the ciphertext, so keys wrapped under older versions stay readable after rotation as long as
  those versions are enabled. A disabled or destroyed version is `not_configured`, not tampering.
- **Integrity**: following Google's data-integrity guidance, every request carries CRC32C checksums
  and every response is checked: `verified_plaintext_crc32c`,
  `verified_additional_authenticated_data_crc32c` and `ciphertext_crc32c` on wrap, `plaintext_crc32c`
  on unwrap. A mismatch fails closed with the kind `other` and yields no key.
- **Errors** keep only the gRPC status code, never the SDK's text: `Unavailable`, `DeadlineExceeded`,
  `ResourceExhausted`, `Internal` become `unavailable`; `PermissionDenied`, `Unauthenticated` become
  `denied`; `InvalidArgument` on unwrap becomes `invalid`; `NotFound`, `FailedPrecondition` become
  `not_configured`; anything else is `other`.
- **Packaging**: build with `-tags nokms_gcp` to leave the Cloud KMS SDK out of the binary (ADR 0022).

### Testing and manual verification

Automated tests run the shared conformance suite against an in-process fake gRPC Cloud KMS server
with real AES-GCM per key version, rotation, CRC32C fields and error injection (ADR 0023). Google
provides no Cloud KMS emulator, so before each release also run the opt-in test against real Cloud KMS:

1. Create a test key (software protection is enough) and a service account, or use your own ADC:

   ```sh
   gcloud kms keyrings create cipherframe-test --location=europe-west1
   gcloud kms keys create wrap-test --keyring=cipherframe-test --location=europe-west1 \
     --purpose=encryption
   gcloud kms keys add-iam-policy-binding wrap-test --keyring=cipherframe-test \
     --location=europe-west1 --member="serviceAccount:SA@PROJECT.iam.gserviceaccount.com" \
     --role=roles/cloudkms.cryptoOperator
   gcloud kms keys add-iam-policy-binding wrap-test --keyring=cipherframe-test \
     --location=europe-west1 --member="serviceAccount:SA@PROJECT.iam.gserviceaccount.com" \
     --role=roles/cloudkms.viewer
   ```

2. Run the suite with Application Default Credentials (`gcloud auth application-default login` or
   `GOOGLE_APPLICATION_CREDENTIALS`):

   ```sh
   CIPHERFRAME_TEST_GCP_KMS_KEY_NAME=projects/PROJECT/locations/europe-west1/keyRings/cipherframe-test/cryptoKeys/wrap-test \
     go test -count=1 -run TestRealGCPKMS -v ./internal/kms/gcpkms/
   ```

3. Check rotation by hand: `gcloud kms keys versions create --key=wrap-test --keyring=cipherframe-test
   --location=europe-west1 --primary`, restart the service, create a new content key, and confirm it
   records the new version while a key created before the rotation still plays.
4. Check the outage and denial paths: remove the IAM binding (expect `denied`, API `internal_error`)
   and block egress to `cloudkms.googleapis.com` (expect `dependency_unavailable`).
5. Delete the test key versions when done (`gcloud kms keys versions destroy`).

## Versioning

KEKs are versioned. The local provider takes `CIPHERFRAME_KMS_LOCAL_KEKS` as `version:base64`
entries (each exactly 32 bytes) and `CIPHERFRAME_KMS_LOCAL_KEK_CURRENT`, the same pattern as API-key
peppers (ADR 0016). To rotate, add a new version, point `..._CURRENT` at it and restart: new content
keys use it and old ones still unwrap under their recorded version. Re-wrapping existing keys onto the
new version is M2-4. Remove an old version only after no content key refers to it.

## Envelope and associated data

The local provider uses AES-256-GCM from the Go standard library with a random 96-bit nonce per wrap
(ADR 0020). The stored ciphertext is `format version (1 byte) | nonce (12 bytes) | sealed key`.

The content key manager binds each wrapped key to its slot with associated data, a canonical
length-prefixed encoding of:

`envelope version | asset id | content key id | provider | KEK key id | KEK version`

(one byte for the version, then a 4-byte big-endian length and the bytes of each text field). Moving a
wrapped key to another asset or key row, or editing the recorded provider, KEK id or KEK version in the
database, makes unwrapping fail. The local provider also authenticates its own format byte.

## Content key lifecycle

- **Create**: one random 16-byte AES-128 key per asset from `crypto/rand`, wrapped by the current
  provider and inserted in the caller's transaction. The `content_keys` table has a unique
  constraint on the asset, so a second create for the same asset returns `conflict` and never a second
  key (I7).
- **Read**: unwrap through the provider recorded in the row. The plaintext key lives only inside a
  `ContentKey` value whose printed, JSON, text and log forms are all `[redacted]`.
- **Destroy**: deletes the row, in the caller's transaction. This is what crypto-shredding (M6) calls:
  the row is destroyed, not flagged, so remaining ciphertext copies cannot be unwrapped.
- Tenant scope: every read, create and destroy goes through the asset's tenant. Another tenant's asset
  is `not_found`.

## The local development provider

`local` exists so the Compose stack and the test suites run without a cloud account. It holds KEKs in
process memory and in configuration, which is exactly what the production providers avoid. It is
therefore **development only**:

- the process refuses to start with it when `CIPHERFRAME_ENV=production` (the loader and the provider
  both check), and a `dev-placeholder-` KEK is rejected in production;
- it logs a warning at every start that it is development-only.

## Operations

- **Re-wrap** (M2-4): re-wraps content keys under a new KEK version without re-encrypting media.
- **Re-key** (M10-4, optional): re-encrypts an asset's segments under a new content key and destroys
  the old one.
- **Crypto-shredding** (M6): destroying the content key row makes every copy of the ciphertext
  unreadable.

## Failure behaviour

If the key provider is unavailable, key requests fail closed with a clear error and no key material
in logs (I11). A provider error never yields a key, and an unknown error is never reported as
success.

## What this does not protect against

- Standard HLS AES-128 is **not DRM**. A viewer with a valid session receives the content key, so the
  video can be recorded or reassembled during the session. Delivering the key to authorized players is
  by design.
- Compromise of the operator's KMS credentials exposes every content key. The same holds for the
  local provider's KEKs, which sit in configuration.
- Losing every KEK (or the KMS key itself) makes all assets permanently unreadable. Back up KEKs and
  keep old versions until no content key uses them.
- An attacker who can both write to the database and call the provider can still obtain keys the
  provider would unwrap; associated data stops moving or editing records, not a compromised provider.
- Re-wrapping and re-keying do not help against plaintext already saved.
