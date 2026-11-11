# Integrity and verifiable deletion

> Status: skeleton (M0-4). The design is pending gates P9 (hashing, Merkle, canonical JSON,
> signatures) and P10 (timestamp authority recommendations).

## Integrity manifests

For each asset Cipherframe hashes every artifact it produced, builds a Merkle tree, and signs a
manifest that records the pipeline version, encoder settings and branding. Signing keys have key ids
and rotate; verification keys are published at `/.well-known/cipherframe-keys.json`.

## Verifiable deletion

The purge job:

1. enumerates storage under the asset's prefixes (it does not trust the database alone),
2. batch-deletes every object, including subtitles, thumbnails and other derived artifacts,
3. destroys the content key (the row is destroyed, not flagged),
4. re-lists to confirm nothing is left,
5. signs a deletion record with object counts per artifact kind.

The record stays fetchable after the asset is gone.

## Anchoring (optional)

When an RFC 3161 Time-Stamping Authority is configured, Cipherframe timestamps the digest of each
signed record. It is off by default; records without a timestamp are reported as "unanchored".

## Verifying

The verifier needs **public keys only**. Its three outcomes are: "ours", "modified version of ours",
and "cannot say". Network, permission and timeout errors are reported as such, never as "tampered" or
"missing".

## What this does not protect against

- A deletion record proves what Cipherframe deleted and that the key was destroyed. It cannot prove
  that nobody kept a plaintext copy.
- Without a timestamp authority, a record's time is only as trustworthy as the operator's clock.
- A compromised signing key can sign false records; rotation limits the damage but does not undo it.

## Signing keys

Manifests and deletion records are signed with Ed25519 keys that Cipherframe generates (ADR 0033).
The keys belong to the deployment, not to a tenant: one published key set verifies the records of
every tenant.

**Custody.** A key's 32-byte seed is generated with the system's random source and wrapped by the
configured KMS provider with the envelope scheme of content keys (ADR 0020). The associated data
binds the purpose `signing-key`, the key id, the algorithm, and the provider, KEK id and KEK version
that wrapped it, so an envelope copied to another key's row, or reused as another kind of key, does
not open. The worker unwraps the seed in memory and signs in-process. An unwrapped seed is cached
for at most five minutes and zeroed when it is evicted; it is never logged, stored or returned. If
the key service is unavailable the operation fails with `503 dependency_unavailable` and no key is
created or used.

**The key set.** `GET /.well-known/cipherframe-keys.json`, served by both the edge (public) and the
api listener, needs no authentication, allows any origin (`Access-Control-Allow-Origin: *`) and is
sent with `Cache-Control: public, max-age=300`. Each process caches it for at most 60 seconds, so a
rotation or retirement is visible within a minute.

```json
{
  "keys": [
    {
      "keyid": "sk_01k9z3m5q8r7s2t4v6w8x0y1zg",
      "alg": "ed25519",
      "public_key": "<raw 32-byte public key, standard base64>",
      "status": "retired",
      "created_at": "2026-11-12T09:00:00Z",
      "retired_at": "2027-02-01T09:00:00Z"
    },
    {
      "keyid": "sk_01kbq2v8h3w9d5f7j1m4n6p8rs",
      "alg": "ed25519",
      "public_key": "<base64>",
      "status": "active",
      "created_at": "2027-01-15T09:00:00Z"
    }
  ]
}
```

Keys are ordered by `created_at`. A signature names its key by `keyid`; a verifier looks that id up
here and needs nothing else. `retired_at` is present only on a retired key. The set carries no
tenant and no secret.

**Life cycle.**

- The first `worker` or `api` process to start creates the first key if the deployment has none.
  An advisory lock makes concurrent starts produce exactly one.
- **Rotate** (`POST /v1/signing-keys/rotate`, `admin` scope) creates a new key and makes it the
  current signer. The previous key stays `active`: it is still published and still verifies, and it
  stops signing. Several keys can be active at once; exactly one is current.
- **Retire** (`POST /v1/signing-keys/{key_id}/retire`) marks a key `retired`. It stays published
  with `status: retired`, so records it signed still verify, and it never signs again. The current
  key cannot be retired (`409 conflict`): rotate first. Retiring a retired key changes nothing.
- Keys are **never destroyed** in M5, and the wrapped seed of a retired key stays in the database.
  Verification needs only the public key, so destroying a retired seed would not break old records;
  a later milestone may add it.
- A rotation and a retirement are audited (`signing_key.rotate`, `signing_key.retire`) against the
  admin key that made them. The first key, created at startup, has no caller and is logged instead.

To respond to a suspected worker compromise: rotate, then retire the old key once the records it
signed that you want to keep trusting have been re-signed or you accept that its records are
suspect. A retired key that leaked still verifies whatever it signed, including forgeries; the key
set does not yet distinguish "retired" from "revoked as compromised".

**KEK rotation.** Signing key envelopes are not moved by the `kms.rewrap` job, and the startup KEK
check does not cover them. A KEK version must stay configured while a signing key wrapped under it
is current; rotating the signing key re-wraps the signer under the current KEK.
