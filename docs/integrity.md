# Integrity and verifiable deletion

> Status: the primitives described under "Construction" and the signed manifest written by the
> pipeline (see "Manifest format") are implemented (ADR 0033, gate P9). The endpoints that serve
> manifests and proofs follow in M5-3. Timestamp
> authority recommendations remain pending gate P10.

## Integrity manifests

For each asset Cipherframe hashes every artifact it produced, builds a Merkle tree, and signs a
manifest that records the pipeline version, encoder settings and branding. Signing keys have key ids
and rotate; verification keys are published at `/.well-known/cipherframe-keys.json`.

## Manifest format

The asset pipeline builds one manifest per asset after it has stored every object and before it
marks the asset ready (package `internal/integrity/manifest`). The manifest is encoded as canonical
JSON (see "Canonical JSON"), signed as a DSSE envelope with payload type
`application/vnd.cipherframe.manifest+json`, and stored in the `asset_manifests` table in the same
transaction that moves the asset to `ready`. A retry removes the previous manifest before it builds
a new one. The envelope is kept in the database only; it is not an object in the delivery bucket.
A later release serves it through the API.

Rules: member names are lower_snake_case; there are no floating-point numbers (bandwidth and sizes
are integers, the frame rate is a rational string such as `"30000/1001"`); hashes are lowercase
hex; times are RFC 3339 in UTC with second precision. Every `path` is relative to the asset's HLS
prefix, the same form as the variant URIs in the master playlist. The manifest never holds a bucket
name or an object key, and it never names the source object: the source appears only as the SHA-256
and size recorded at ingest. A segment's hash covers the bytes as stored, so for a media segment it
is the hash of the ciphertext.

| Member | Content |
| --- | --- |
| `schema` | `cipherframe.manifest/v1` |
| `asset_id`, `tenant_id` | The prefixed ids of the asset and its tenant. |
| `created_at` | When the manifest was made. |
| `pipeline_version` | The Cipherframe version that ran the pipeline. |
| `encoder` | `ffmpeg` (first line of `ffmpeg -version`), `video_codec`, `preset`, `frame_rate`, `segment_seconds`, `keyframe_seconds`, `encryption` (`AES-128`), and `rungs`: per rendition `name`, `crf`, `maxrate_kbps`, `bufsize_kbps`, `audio_kbps`. |
| `renditions` | In ladder order: `name`, `width`, `height`, `bandwidth`, `segment_count`, `init` and `segments` (each `path`, `sha256`, `size`, segments in playlist order), and `merkle_root`. |
| `artifacts` | The master playlist (`kind` `master`) and each media playlist (`kind` `playlist`, with its `rendition`): `kind`, `path`, `sha256`, `size`. |
| `top_level` | `order`, the leaf labels of the top-level tree, and `root`. |
| `source` | `sha256` and `size` of the uploaded original. |
| `masked` | Only for an asset with a face-masked variant (ADR 0036); see "The masked variant". |

Trees. Rendition `merkle_root`: leaves are the init segment and then the media segments in
playlist order, each leaf's data being the artifact's 32-byte SHA-256. Top-level `root`: leaves in
this fixed order, each rendition's 32-byte `merkle_root` in ladder order, then the SHA-256 of the
master playlist, then the SHA-256 of each media playlist in ladder order; `order` lists their labels
(`rendition:<name>`, `master`, `playlist:<name>`).

An example, with obviously fake hashes and one rendition of two segments (shown indented; the
signed bytes are the canonical form without whitespace):

```json
{
  "schema": "cipherframe.manifest/v1",
  "asset_id": "ast_00000000000000000000000001",
  "tenant_id": "ten_00000000000000000000000001",
  "created_at": "2026-11-12T10:30:15Z",
  "pipeline_version": "v1.2.3",
  "encoder": {
    "ffmpeg": "ffmpeg version 7.1 Copyright (c) 2000-2024 the FFmpeg developers",
    "video_codec": "libx264", "preset": "medium", "frame_rate": "30000/1001",
    "segment_seconds": 6, "keyframe_seconds": 2, "encryption": "AES-128",
    "rungs": [{"name": "720p", "crf": 23, "maxrate_kbps": 3000, "bufsize_kbps": 6000, "audio_kbps": 128}]
  },
  "renditions": [{
    "name": "720p", "width": 1280, "height": 720, "bandwidth": 2500000, "segment_count": 2,
    "init": {"path": "720p/init.mp4", "sha256": "aa00...aa", "size": 812},
    "segments": [
      {"path": "720p/seg-0.m4s", "sha256": "bb00...bb", "size": 1048592},
      {"path": "720p/seg-1.m4s", "sha256": "cc00...cc", "size": 524304}
    ],
    "merkle_root": "dd00...dd"
  }],
  "artifacts": [
    {"kind": "master", "path": "master.m3u8", "sha256": "ee00...ee", "size": 310},
    {"kind": "playlist", "rendition": "720p", "path": "720p/playlist.m3u8", "sha256": "ff00...ff", "size": 280}
  ],
  "top_level": {"order": ["rendition:720p", "master", "playlist:720p"], "root": "1100...11"},
  "source": {"sha256": "2200...22", "size": 52428800}
}
```

### The masked variant

An asset created with `mask_faces` is first ready with the original variant and a manifest as above.
When its masked variant is published (`asset.mask`), the manifest is built again with one more member,
`masked`, and signed again; the new envelope replaces the old one in the same transaction that registers
the masked objects and sets `masking_state` to `ready`. The schema stays `cipherframe.manifest/v1`: a
verifier that does not know `masked` still checks the signature and the original variant, whose members
are carried over exactly as they were signed.

`masked` has the same shapes as the top-level members, with every `path` relative to the masked
variant's HLS prefix (`masked/hls/`, the original's being `hls/`), and its own trees. Paths repeat
between the variants (`720p/seg-0.m4s` exists in both), so a hash is always checked against the
prefix of the section it appears in. Segments of the two variants are encrypted under different content
keys, so their hashes differ even where the picture does not.

| `masked` member | Content |
| --- | --- |
| `created_at` | When the masked variant was published. |
| `faces_detected` | Frames in which the masker found at least one face (held boxes do not count). |
| `frames` | Frames the masker wrote. |
| `rungs` | The encoder setting of each masked rendition (the ladder is chosen from the masked file). |
| `renditions`, `artifacts`, `top_level` | As at the top level, for the masked variant. |

The `top_root` column stays the original variant's top-level root; the masked variant's is
`masked.top_level.root` in the envelope. The encoder block at the top level describes the original
variant; the masked file goes through the same code and the same encoder settings. An asset whose
masking failed, or is still pending, has no `masked` member and keeps its first manifest.

The `asset_manifests` row also records the `key_id` of the signer, the SHA-256 of the payload and
the top-level root as separate columns, so a lookup does not need to parse the envelope. A signer
failure while processing is a retried failure like any other; the asset does not become ready
without a manifest.

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
hashes of the other artifacts in the order the manifest records (see "Manifest format").

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
