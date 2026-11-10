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
