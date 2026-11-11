# Integrity and verifiable deletion

> Status: the primitives described under "Construction" are implemented (M5-1a, ADR 0033, gate
> P9). The manifest fields, signing-key storage and endpoints follow in M5-1 to M5-3. Timestamp
> authority recommendations remain pending gate P10.

## Integrity manifests

For each asset Cipherframe hashes every artifact it produced, builds a Merkle tree, and signs a
manifest that records the pipeline version, encoder settings and branding. Signing keys have key ids
and rotate; verification keys are published at `/.well-known/cipherframe-keys.json`.

## Construction

This section is meant to be enough to write an independent verifier. A verifier needs SHA-256,
Ed25519, a JSON parser and the published public keys; it never needs a secret. The reference code
is in `internal/integrity` (`merkle`, `jcs`, `dsse`, `verify`), which depends only on the Go
standard library.

### Hashing and Merkle trees (RFC 9162 section 2.1)

All hashes are SHA-256 (32 bytes).

- Leaf hash of data `d`: `SHA-256(0x00 || d)`.
- Interior hash of children `l` and `r`: `SHA-256(0x01 || l || r)`.
- Empty tree: `SHA-256("")` (hash of zero bytes, with no prefix).
- Tree over `n > 1` leaves: let `k` be the largest power of two strictly smaller than `n`. The tree
  hash is the interior hash of the tree over the first `k` leaves and the tree over the remaining
  `n - k` leaves. A single leaf's tree hash is its leaf hash. The shape is therefore left-heavy
  and complete on the left; it is not padded and no leaf is duplicated.
- Streaming: the root can be computed while leaves arrive by keeping the roots of the perfect
  subtrees covering the leaves so far (one per set bit of the count). Appending a leaf merges
  equal-sized neighbours; the final root folds the stack from the right. Memory is O(log n).

Per ADR 0033, there is one tree per rendition. Its leaves are the init segment and then the media
segments in playlist order, and each leaf's data is that artifact's 32-byte SHA-256 (so the leaf
hash is `SHA-256(0x00 || sha256(artifact))`). A top-level tree combines the rendition roots and the
hashes of the other artifacts in the order the manifest records. The manifest fields are fixed in
M5-1.

Inclusion proof (audit path), RFC 9162 sections 2.1.3.1 and 2.1.3.2. For leaf index `m` (0-based) in
a tree of `n` leaves, `PATH(m, D[n])` is empty when `n = 1`; otherwise, with `k` as above, it is
`PATH(m, D[0:k])` followed by the tree hash of `D[k:n]` when `m < k`, and `PATH(m - k, D[k:n])`
followed by the tree hash of `D[0:k]` otherwise. To verify, set `fn = m`, `sn = n - 1`, `r = leaf
hash`, and for each path element `p`: fail if `sn = 0`; if `fn` is odd or `fn = sn`, set
`r = H(0x01 || p || r)` and, while `fn` is even and not zero, shift both `fn` and `sn` right by
one; otherwise set `r = H(0x01 || r || p)`; then shift both right by one. Accept when `sn = 0` and
`r` equals the root. A proof binds the leaf to the root only through the sibling hashes, so the
tree size must come from an authenticated source (the signed manifest), not from the prover.

The test suite reproduces the published Certificate Transparency vectors (roots of the 0 to 8 leaf
trees and inclusion proofs from them) and checks every index of every tree of 1 to 257 leaves.

### Canonical JSON (RFC 8785)

Signed documents are serialised with the JSON Canonicalization Scheme: no insignificant
whitespace; object members sorted by the UTF-16 code units of their (unescaped) names; strings
escaped as `\b \t \n \f \r \" \\`, other control characters below 0x20 as lower-case `\u00xx`, and
everything else literally in UTF-8; numbers as ECMAScript `Number::toString` of the IEEE 754
double. Input must be I-JSON: valid UTF-8, no duplicate member names, no lone surrogate escapes.
Cipherframe documents carry only integers up to 2^53-1, strings, booleans, null, arrays and
objects; values that do not fit (for example 64-bit counters) are written as strings, and the
reference `jcs.Marshal` rejects a larger Go integer instead of rounding it. A verifier does not
need to canonicalize at all: it verifies the exact payload bytes of the envelope.

### DSSE envelope

Signatures use DSSE v1 (secure-systems-lab/dsse, `envelope.md` and `protocol.md`) with Ed25519.

```json
{"payloadType": "application/vnd.cipherframe.manifest+json",
 "payload": "<base64 of the canonical JSON document>",
 "signatures": [{"keyid": "<key id>", "sig": "<base64 of the 64-byte Ed25519 signature>"}]}
```

The signed bytes are `PAE(payloadType, payload)`:

```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

where `SP` is one space (0x20), `LEN` is the byte length in ASCII decimal with no leading zeros,
and `payload` is the decoded bytes. The spec example is `PAE("http://example.com/HelloWorld",
"hello world") = "DSSEv1 29 http://example.com/HelloWorld 11 hello world"`.

Payload types: `application/vnd.cipherframe.manifest+json` for integrity manifests and
`application/vnd.cipherframe.deletion+json` for deletion records. A verifier must check the
payload type against the one it expects before trusting the payload; the type is inside the signed
bytes, so relabelling an envelope breaks the signature.

Encoding: Cipherframe writes standard padded base64. The DSSE spec lets either the standard or the
URL-safe alphabet be used and requires consumers to accept both; the reference decoder accepts
either, padded and canonical, and rejects line breaks. Decoding is strict: unknown or duplicate
members, wrong member-name case, null or non-string values are errors. Limits: envelope 8 MiB, at
most 16 signatures, keyid and payloadType at most 256 bytes. An envelope may carry several
signatures (key rotation); one valid signature by a trusted key is enough, a signature by an
unknown key is ignored, and duplicate keyids are rejected. `keyid` is optional in the DSSE spec;
Cipherframe always sets it, and a signature without one is treated as coming from an unknown key.

### Outcomes

The verifier library classifies every result into one of five outcomes (package `verify`):

| Outcome | Meaning |
| --- | --- |
| verified | Every check passed. |
| tampered | A mismatch was proven: a Merkle path leads to a different root, or a trusted key's signature does not verify. |
| untrusted-key | The document is well formed but no signature came from a trusted key. |
| malformed | The input is not a valid document (bad JSON or base64, wrong payload type, impossible proof shape). |
| cannot-say | Anything else: network, permission, timeout and storage errors, and unknown errors. |

Only an error that wraps the specific sentinel becomes tampered, untrusted-key or malformed.
Everything else is cannot-say, never "tampered" or "missing".

References: RFC 9162 (Certificate Transparency Version 2.0) section 2.1; RFC 8785 (JSON
Canonicalization Scheme); DSSE v1 specification, https://github.com/secure-systems-lab/dsse.

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
