# Encryption

> Status: M2-1 to M2-5 implemented (key-provider interface, envelope encryption, content keys,
> local development provider, Vault/OpenBao, AWS KMS and GCP Cloud KMS providers, re-wrap, failure
> behaviour) and M3-8 (segment encryption in the processing pipeline).

## Layers

1. **Segments**: HLS AES-128 with explicit per-segment IVs, under one content key per asset (I7).
2. **Content key at rest**: envelope-encrypted with an AEAD, bound to the asset id and key id as
   associated data, wrapped by a key-encryption key (KEK).
3. **KEK**: held by a key management provider. Every wrapped key records provider, key id and
   version.

| Provider | Status |
|---|---|
| AWS KMS (`awskms`) | implemented (M2-2); see below |
| HashiCorp Vault Transit and OpenBao (`vault`) | implemented (ADR 0021) |
| GCP Cloud KMS (`gcpkms`) | implemented (M2-2); see below |
| Local development provider (`local`) | implemented; **development only** (ADR 0019) |

## Segment encryption (M3-8)

The processing pipeline ([architecture.md](architecture.md#processing-pipeline)) encrypts every media
segment itself, in process. FFmpeg's HLS muxer cannot encrypt fMP4 segments, so FFmpeg writes plain
segments into the job's private work directory and Cipherframe encrypts each one before it is
uploaded.

- **Cipher.** AES-128 in CBC mode with PKCS#7 padding, exactly the HLS `METHOD=AES-128` of RFC 8216
  section 4.3.2.4, so any HLS player decrypts it. The result is 1 to 16 bytes longer than the plaintext
  (a segment that is already a multiple of 16 bytes gains a whole padding block).
- **Key.** The asset's content key (one random 16-byte key per asset, see below). It is created once
  before transcoding, read once per job, kept only in memory and cleared when the job ends.
- **IV.** Every segment gets its own random 16-byte IV from `crypto/rand`, written in the playlist as
  `IV=0x<32 hex digits>` on that segment's `EXT-X-KEY` tag. An explicit IV per segment avoids the
  default of deriving the IV from the media sequence number: every fMP4 segment starts with the same
  box header, and reusing one CBC IV under one key would reveal whether two segments begin with the
  same plaintext block. IVs are not secret.
- **Stored playlists.** Each `EXT-X-KEY` carries `URI="cipherframe-key"`, a placeholder. The edge
  (M4) rewrites it to a session-bound key URL when it serves a playlist, so what is stored in the
  delivery bucket never contains a token, a session ID or a real key location.
- **Init segments are not encrypted.** The `EXT-X-MAP` tag comes before the first `EXT-X-KEY`, and by
  RFC 8216 a key applies only to init segments declared after it, so players fetch the init segment
  without a key. It holds codec configuration (the avcC and esds boxes, track sizes and timescales)
  and no media samples. Anyone who can read the delivery bucket learns the codec, profile, level and
  frame size of a rendition from it; they learn that from the master playlist as well.
- **Integrity.** The SHA-256 of the stored (encrypted) bytes of every object is recorded in
  `asset_artifacts`. CBC provides confidentiality, not authentication: a modified segment is not
  detected by the player's decryption (at best the padding check fails); the recorded hashes are what
  integrity checks (M6) compare against.
- **Plaintext.** The plaintext of a segment exists in the worker's work directory until it is read
  (then the file is deleted) and in a memory buffer that is cleared right after encryption. The
  content key, the IVs' relationship to it and the plaintext never appear in logs, errors, job
  arguments or storage; the pipeline's unit tests scan logs, errors and artifacts for the key in raw,
  hex and base64 form.
- **Tests.** `internal/hls` checks the cipher against the NIST SP 800-38A CBC vectors and the padding
  against an independent single-block AES computation. The pipeline integration test fetches segments
  straight from storage and shows that FFprobe cannot parse them, then decrypts them with the key and
  the playlist's IV and shows that FFprobe can.

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

## Versioning

KEKs are versioned. The local provider takes `CIPHERFRAME_KMS_LOCAL_KEKS` as `version:base64`
entries (each exactly 32 bytes) and `CIPHERFRAME_KMS_LOCAL_KEK_CURRENT`, the same pattern as API-key
peppers (ADR 0016). To rotate, add a new version, point `..._CURRENT` at it and restart: new content
keys use it and old ones still unwrap under their recorded version. Re-wrap existing keys onto the
new version as described in [Rotation and re-wrap](#rotation-and-re-wrap). Remove an old version only
after no content key refers to it; the server refuses to start if one does.

## Rotation and re-wrap

Re-wrap moves stored content keys onto the current KEK. It unwraps each key with the provider and KEK
version recorded in its row, wraps the **same 16 key bytes** under the current provider's current
KEK, and stores the new ciphertext. The content key never changes, so no media is re-encrypted and
players are unaffected. The associated data of the new wrap names the new provider, KEK id and KEK
version, so the old ciphertext is not valid under the new binding and the new one is not valid under
the old.

**Procedure for a new KEK version (same provider)**

1. Rotate the KEK: for `local`, add a version to `CIPHERFRAME_KMS_LOCAL_KEKS` and move
   `..._CURRENT`; for Vault, rotate the Transit key; for GCP, add a primary version. (AWS KMS rotates
   inside the key and needs no re-wrap.) Restart the processes.
2. `cipherframe-server admin kms-usage` shows how many content keys each version wraps.
3. `cipherframe-server admin kms-rewrap --wait` (a `worker` must be running).
4. `admin kms-usage` again: every key is on the current version.
5. **Disable the old KEK version at the provider** (Vault `min_decryption_version`, KMS key version
   disable or destroy, remove the local version from configuration). This step is what makes the old
   ciphertext useless; see the limits below.

**Procedure for moving between providers** (for example `local` to `vault`)

1. Configure the new provider as `CIPHERFRAME_KMS_PROVIDER` and list the old one in
   `CIPHERFRAME_KMS_UNWRAP_PROVIDERS`. Its settings are loaded and validated like the current
   provider's. Unwrap-only providers are never asked to wrap.
2. Restart; run `admin kms-rewrap --wait`; check `admin kms-usage`.
3. Remove the old provider from `CIPHERFRAME_KMS_UNWRAP_PROVIDERS` and disable its KEK.

**Startup check.** Before serving, every role lists the distinct `(provider, KEK id, KEK version)` in
`content_keys` and refuses to start when a provider is not configured or, for `local`, a version is
missing. Remote providers keep their versions server-side, so they are checked for presence only; a
missing remote version fails on the first request for that key, as `denied` or `not_configured`.

**How the job works.** `kms.rewrap` selects up to `batch_size` rows (default 100, at most 1000) whose
KEK differs from the current one. Provider calls happen outside the transaction; for each key it
unwraps, wraps, and unwraps the new ciphertext to check that it reads back the same bytes before the
old ciphertext is replaced. The updates then commit in one transaction, guarded so each row changes
only while it still names the old KEK, so concurrent runs cannot overwrite each other. If keys remain,
the next run is enqueued in the same transaction as the last update, so a crash resumes cleanly. A run
on an already re-wrapped database changes nothing. Running two chains at once is safe but wasteful.

**Errors in the job.** An unavailable key service gives `dependency_unavailable` and the job retries
with backoff (15 s doubling to 30 min, five attempts by default). Rows already re-wrapped in the failed
run stay re-wrapped and the rest are untouched. A key that fails authentication (tampered ciphertext,
wrong binding) is an integrity failure: the job is cancelled at once and appears in the dead-letter
list with the code `internal_error` only. It is logged with the content key id, asset id, provider
and KEK version, never a value. Investigate the row before retrying the job.

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

## The Vault Transit provider

`vault` wraps content keys with a Transit key held by HashiCorp Vault or OpenBao, so the KEK never
reaches Cipherframe. It talks to the Transit HTTP API directly (no Vault SDK) and is tested in CI
against both servers (ADR 0021). Settings are in the `CIPHERFRAME_KMS_VAULT_*` rows of
[usage.md](usage.md).

- **Key**: create an AEAD Transit key, for example
  `vault write -f transit/keys/cipherframe type=aes256-gcm96` (`bao` for OpenBao). The
  content-key binding (asset, slot, provider, KEK id and version) is sent as Transit's
  `associated_data`, so the key type must authenticate it: `aes256-gcm96`, `aes128-gcm96` or
  `chacha20-poly1305`. The provider checks the type on first use and refuses any other.
  Cipherframe never creates the key; it reads the key's metadata and fails with `NotConfigured` if
  it is missing (Transit would otherwise create it on first encrypt).
- **Token policy**: grant only what is used.

  ```hcl
  path "transit/keys/cipherframe"    { capabilities = ["read"] }
  path "transit/encrypt/cipherframe" { capabilities = ["update"] }
  path "transit/decrypt/cipherframe" { capabilities = ["update"] }
  ```

  Use a renewable or periodic token, or an auth method that writes the token to a file read through
  `CIPHERFRAME_KMS_VAULT_TOKEN_FILE`. The provider does not renew tokens; an expired token shows as
  `ErrDenied`.
- **Recorded values**: `Wrapped.KeyID` is the Transit key name and `Wrapped.Version` is the number in
  Vault's `vault:vN:` ciphertext prefix, so the version recorded is the one Vault actually used.
  `Current` reads the key's `latest_version`. The ciphertext stored is Vault's ciphertext string.
- **Rotation**: `vault write -f transit/keys/cipherframe/rotate`. New wraps use the new version at
  once, with no restart; old ciphertext still unwraps while `min_decryption_version` allows it.
  Raising `min_decryption_version` above a version still in use makes those keys fail with
  `ErrNotConfigured`: re-wrap first (M2-4).
- **Ciphertext format**: the provider accepts only canonical base64 after the `vault:vN:` prefix, so a
  changed ciphertext fails even where a lenient decoder would ignore the change.
- **Errors**: connection failures, timeouts, redirects (never followed, so the token cannot be sent
  elsewhere), HTTP 429 and 5xx (sealed or standby server included) are `ErrUnavailable`; 401 and 403
  are `ErrDenied`; a failed authentication or malformed ciphertext is `ErrInvalid`; a missing key,
  mount or key version (404, or Vault's "key not found", "too old", "too new") is `ErrNotConfigured`;
  anything else is `Other`. An error carries only the operation, the HTTP status and a fixed
  category, never the server's text, because Vault can echo request input.
- **TLS**: production requires `https`. `CIPHERFRAME_KMS_VAULT_CA_FILE` replaces the system roots;
  TLS 1.2 is the minimum.

## The AWS KMS provider

`awskms` wraps content keys with the KMS `Encrypt` and `Decrypt` operations under one symmetric
encryption key, so the KEK never leaves KMS. It is built into the standard binary and image; a build
with the `nokms_aws` tag leaves it out and refuses to start when it is configured (ADR 0022).

- **Key identity.** `CIPHERFRAME_KMS_AWS_KEY_ID` is a key ARN, an alias ARN or `alias/name`. `Current`
  resolves it with `DescribeKey` to the key's ARN, and every wrapped key records that ARN as its KEK
  id. `Unwrap` sends the stored ARN to KMS, so a ciphertext opens only under the key that wrapped it,
  and keeps working after an alias is pointed at another key. Keep the old key enabled until no
  content key refers to it.
- **No visible version.** AWS rotates the backing key material transparently (automatic rotation) and
  keeps old material for decryption, so there is nothing for a caller to choose. The recorded KEK
  version is the constant `managed`. Rotation by AWS needs no action and no re-wrap; moving to a
  different KMS key is the M2-4 re-wrap.
- **Associated data.** KMS has no separate associated-data input. The associated data is sent as the
  encryption context, base64-encoded under the context key `cf-aad`, and KMS fails `Decrypt` when it
  differs. It contains the asset id and content key id, so those ids appear in CloudTrail entries for
  the key. Plaintext keys never do.
- **Credentials.** `CIPHERFRAME_KMS_AWS_ACCESS_KEY_ID` and `..._SECRET_ACCESS_KEY` follow the S3
  rules (see `docs/usage.md`): both set means a static key pair, both empty means the AWS SDK default
  credential chain (environment, shared config, container or instance role; preferred in
  production), and production refuses to start with the variables absent. Absent in development also
  uses the default chain, because KMS has no anonymous access.
- **Permissions.** The identity needs `kms:DescribeKey`, `kms:Encrypt` and `kms:Decrypt` on the key.
- **Errors.** A disabled, pending-deletion or missing key is `ErrNotConfigured`; access denied or
  rejected credentials is `ErrDenied`; a tampered ciphertext, a different associated data or a
  mismatched key is `ErrInvalid`; throttling, 5xx, network failures and timeouts are `ErrUnavailable`
  (the SDK retries them within `CIPHERFRAME_KMS_AWS_TIMEOUT`); everything else is `Other`. Errors carry
  only the AWS error code and HTTP status, never the SDK's text, which can include ARNs.
- **Limits.** KMS `Encrypt` accepts at most 4096 bytes; content keys are 16 bytes.

Testing: normal CI runs the conformance suite against a pinned `moto` server (ADR 0023). moto differs
from AWS in places (it does not enforce disabled keys on `Encrypt`/`Decrypt`, answers a mismatched
pinned key with `AccessDeniedException`, and does not rotate key material visibly), so before a
release run the opt-in suite against a real key:

```sh
CIPHERFRAME_TEST_AWS_KMS_KEY_ID=alias/cipherframe-test CIPHERFRAME_TEST_AWS_REGION=eu-west-1 \
  go test -count=1 -tags=integration -run TestRealAWSKMS ./internal/kms/awskms/
```

It uses the default credential chain and a symmetric key you can encrypt and decrypt with.

## The GCP Cloud KMS provider

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

## Operations

- **Re-wrap** (M2-4): re-wraps content keys under the current KEK without re-encrypting media
  (see [Rotation and re-wrap](#rotation-and-re-wrap)). Triggered by `admin kms-rewrap`; an HTTP
  trigger is out of scope until the operator API is decided.
- **Re-key** (M10-4, optional): re-encrypts an asset's segments under a new content key and destroys
  the old one.
- **Crypto-shredding** (M6): destroying the content key row makes every copy of the ciphertext
  unreadable.

## Failure behaviour

If the key provider is unavailable, key requests fail closed with a clear error and no key material
in logs (I11). A provider error never yields a key, and an unknown error is never reported as
success.

- **Outage.** `Create`, `Get` and the re-wrap fail with `dependency_unavailable` (HTTP 503,
  retryable). No key is returned, no row is written and no success is reported. A `Create` that
  fails leaves no row, so the caller's transaction can retry cleanly.
- **Integrity failure** (tampered ciphertext, wrong associated data, a key of the wrong length): the
  result is `internal_error`, not retryable for clients, and the log line is the fixed message
  "content key failed authentication (integrity failure)" with the asset id, content key id,
  provider, KEK id and KEK version. Provider error text is never logged or stored.
- **Not configured or denied.** A key whose provider or version is missing, or whose credentials are
  refused, is `internal_error` and logs "content key provider is not usable" with identifiers only.
- **Jobs.** River stores only the error code of a failed attempt. A test provider wrapper
  (`kmstest.Faulty`) injects outages and integrity failures, and a log-scan test asserts that
  neither content key bytes (raw, hex, base64) nor KEK bytes appear in logs or error strings.

## What this does not protect against

- Standard HLS AES-128 is **not DRM**. A viewer with a valid session receives the content key, so the
  video can be recorded or reassembled during the session: an authorized player holds the key and can
  save the segments, and the key is the same for every viewer of the asset. Delivering the key to
  authorized players is by design (invariant I8).
- Segment encryption protects the delivery bucket, not the viewer: whoever can read the bucket sees
  only ciphertext, but the init segment, the playlists, the number and size of segments and the
  renditions' resolutions and bitrates are not hidden.
- CBC without authentication: a tampered segment is not rejected by the cipher. The registered hashes
  detect it only when something checks them.
- Compromise of the operator's KMS credentials exposes every content key. The same holds for the
  local provider's KEKs, which sit in configuration.
- Losing every KEK (or the KMS key itself) makes all assets permanently unreadable. Back up KEKs and
  keep old versions until no content key uses them.
- An attacker who can both write to the database and call the provider can still obtain keys the
  provider would unwrap; associated data stops moving or editing records, not a compromised provider.
- Re-wrapping and re-keying do not help against plaintext already saved.
- **Re-wrap does not help if a KEK was already compromised and ciphertext was copied.** Old
  ciphertext stays decryptable with the old KEK until that KEK is destroyed or disabled, so a copy of
  the database taken before the re-wrap still opens with the old KEK. After a re-wrap, disable the
  old KEK version at the provider. Re-wrap also does not change the content keys themselves; if a
  content key may have leaked, re-key the asset (M10-4).
- While a re-wrap runs, content keys are briefly in process memory (as on every read) and are
  zeroed after use on a best-effort basis; a memory dump of the worker could still expose them.
- The startup check cannot see which versions a remote provider holds; a version that was disabled
  at the provider too early shows up as failed key requests, not as a refusal to start.
