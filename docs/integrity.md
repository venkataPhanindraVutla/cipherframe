# Integrity and verifiable deletion

> Status: the primitives described under "Construction", the signed manifest written by the
> pipeline (see "Manifest format") and the API that serves manifests and proofs and answers
> "is this ours?" (see "Serving manifests and proofs") are implemented (ADR 0033, 0039, gate P9).
> The offline verifier and `cipherframe verify` (M5-4) are implemented, and so are the verified purge
> and the signed deletion record (M6, ADR 0040, ADR 0042). Timestamp authority recommendations remain
> pending gate P10.

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
a new one. The envelope is kept in the database only (as `jsonb`, so the served JSON may order its members
differently from the one written; the signed bytes are the base64 `payload` and are unchanged); it is
not an object in the delivery bucket. The API serves it (see "Serving manifests and proofs").

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
| `faces_detected` | Frames on which at least one face box was applied from a detection, including a detection reused on frames the masker skipped (`CIPHERFRAME_ML_DETECT_EVERY`); boxes kept only by the hold do not count. |
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

## Serving manifests and proofs

The API serves the stored envelope, an inclusion proof for any artifact in it, and a "is this ours?"
check (ADR 0039; routes, scopes and examples in [api.md](api.md#integrity-manifests-proofs-verify-adr-0033-0039)).
All three need an API key with `assets:read` and are tenant-scoped; only the key set is public. The
package `internal/integrity/proof` builds and checks the proofs.

A proof has two levels. For an init or media segment, level one is the RFC 9162 audit path of its
leaf in the rendition tree (`leaf_index`, `tree_size`, `audit_path`, ending at `rendition_root`), and
level two (`top_level`) is the audit path of `SHA-256(0x00 || rendition_root)` in the top-level tree,
ending at `top_level.root`. For a playlist, level one is absent and `top_level` proves the playlist's
hash directly. Both are computed from the signed manifest in the order it records (`top_level.order`,
ladder order, playlist order), never from storage, and each is checked against the recorded root
before it is returned. A proof does not name its signer: a verifier takes the tree sizes and the root
from the signature-checked manifest (`top_level.root`, or `masked.top_level.root` for the masked
variant, whose paths are relative to the masked prefix and which has its own trees).

`POST /v1/verify` maps the result onto the three public outcomes: `ours` (in the manifest, hash
equal), `modified` (path in the manifest, hash different) and `cannot_say` (everything else,
including a stored manifest whose signature does not verify with the published keys, which is also
logged as an error). A hash-only lookup finds candidates in the artifact registry
(`asset_artifacts`, by SHA-256) and confirms each against its signed manifest, so it returns the
manifest path (the object key minus the variant's HLS prefix) and never a bucket or object key.

## Verifiable deletion

`DELETE /v1/assets/{asset_id}` starts the `asset.delete` job (package `internal/purge`). The job:

1. marks the asset `deleting` (playback, new sessions, uploads and the pipeline refuse it from then
   on) and revokes its active playback sessions; an in-flight processing or masking job stops at its
   next check and removes its own output, and the purge waits for it (up to two hours after the
   request) so it cannot upload behind the purge's back;
2. enumerates storage under every prefix of `keys.AssetPrefixes` in both buckets (it does not trust
   the database alone, so an object nobody registered is found too) and aborts an unfinished
   multipart upload;
3. batch-deletes every object, including both variants, tusd's `.info` and `.part` objects and any
   derived artifact (every kind is listed in the registry of package `purge`; a test fails when the
   key builders and the registry drift apart);
4. lists again, and deletes again, until a pass finds nothing. Objects still there after four passes
   fail the job (`purge: objects remain...`), which retries with backoff; after its attempts it is
   dead-lettered and the asset stays `deleting`, so a failed purge is visible and is never reported as
   done. Repeating `DELETE` queues a new job for such an asset;
5. in one transaction destroys the content keys of every variant (the rows are deleted, not flagged),
   removes the artifact registry rows and the manifest, signs the deletion record and stores it, and
   moves the asset to `deleted`. The keys are destroyed only after storage was verified empty, so a
   purge that fails leaves the data encrypted and a retry still knows which keys to name.

The asset row stays as a tombstone (`state: deleted`, no source object key), the audit rows stay, and
the access trail follows its own retention window ([privacy.md](privacy.md)).

### The deletion record

The record is a canonical JSON document (see "Canonical JSON") signed as a DSSE envelope with payload
type `application/vnd.cipherframe.deletion+json`, using the same Ed25519 keys as manifests (see
"Signing keys"). It is stored in `asset_deletion_records` in the transaction that ends in the
tombstone, so a deleted asset always has one, and it outlives everything else of the asset. The API
serves it at `GET /v1/assets/{asset_id}/deletion-record` (`assets:read`; `404 not_deleted` until the
asset is deleted). The rules of the manifest format apply: lower_snake_case members, no floating-point
numbers, hex hashes, RFC 3339 UTC times with second precision.

| Member | Content |
| --- | --- |
| `schema` | `cipherframe.deletion/v1` |
| `asset_id`, `tenant_id` | The prefixed IDs of the asset and its tenant. |
| `requested_at`, `completed_at` | When deletion was requested, and when the purge finished and storage was verified empty. |
| `reason` | `requested` (an API call) or `retention` (the asset's time-to-live ran out). |
| `pipeline_version` | The Cipherframe version that ran the purge. |
| `objects` | One entry per bucket, artifact kind and variant, sorted by those: `bucket` (`source` or `delivery`), `kind` (`source`, `tus_info`, `tus_part`, `master`, `playlist`, `init`, `segment`, `poster`, or `other` for an object nothing in Cipherframe writes), `variant` (`original` or `masked` for HLS objects, absent otherwise), `count`, `bytes`. |
| `objects_deleted`, `bytes_deleted` | The totals of `objects`. |
| `content_keys` | `destroyed` (the count) and `keys`: the `id` and `variant` of each destroyed content key, sorted by id. Never key material. |
| `manifest_root` | The top-level Merkle root (hex) of the asset's manifest as it stood at deletion (the original variant's, the `top_root` column); absent if the asset never had a manifest. |

The record never holds a bucket name, an object key, a file name or anything about a viewer. An
example with fake values (an asset with a masked variant; shown indented, the signed bytes are the
canonical form):

```json
{
  "schema": "cipherframe.deletion/v1",
  "asset_id": "ast_00000000000000000000000001",
  "tenant_id": "ten_00000000000000000000000001",
  "requested_at": "2026-11-14T10:00:00Z",
  "completed_at": "2026-11-14T10:00:07Z",
  "reason": "requested",
  "pipeline_version": "v1.2.3",
  "objects": [
    {"bucket": "delivery", "kind": "init", "variant": "masked", "count": 1, "bytes": 812},
    {"bucket": "delivery", "kind": "init", "variant": "original", "count": 1, "bytes": 812},
    {"bucket": "delivery", "kind": "master", "variant": "masked", "count": 1, "bytes": 310},
    {"bucket": "delivery", "kind": "master", "variant": "original", "count": 1, "bytes": 310},
    {"bucket": "delivery", "kind": "playlist", "variant": "masked", "count": 1, "bytes": 280},
    {"bucket": "delivery", "kind": "playlist", "variant": "original", "count": 1, "bytes": 280},
    {"bucket": "delivery", "kind": "segment", "variant": "masked", "count": 2, "bytes": 1572864},
    {"bucket": "delivery", "kind": "segment", "variant": "original", "count": 2, "bytes": 1572880},
    {"bucket": "source", "kind": "source", "count": 1, "bytes": 52428800},
    {"bucket": "source", "kind": "tus_info", "count": 1, "bytes": 190}
  ],
  "objects_deleted": 13,
  "bytes_deleted": 55577918,
  "content_keys": {
    "destroyed": 2,
    "keys": [
      {"id": "cky_00000000000000000000000001", "variant": "original"},
      {"id": "cky_00000000000000000000000002", "variant": "masked"}
    ]
  },
  "manifest_root": "1100...11"
}
```

### Verifying a deletion record

```sh
cipherframe verify --deletion-record record.json --keys keys.json
```

`record.json` is the response of the endpoint, `keys.json` the published key set (or use
`--keys-url`). The tool checks the envelope's payload type and signature against the key set (active
and retired keys are both trusted) and prints the summary: the outcome, the asset, the times and
reason, the objects per bucket, kind and variant, the destroyed keys and the manifest root. The
library is `offline.OpenDeletion` / `offline.VerifyDeletion`. A deletion record has no file to
compare, so only two public outcomes exist:

| Public outcome | Reason shown | When | Exit |
| --- | --- | --- | --- |
| ours | `verified` | A trusted key's signature covers a well-formed `cipherframe.deletion/v1` payload. | 0 |
| cannot say | `untrusted-key`, `tampered-envelope`, `malformed`, `cannot-say` | No signature from a trusted key; a trusted key's signature does not verify; the input is not a deletion record (a manifest envelope is refused: its payload type differs); an unreadable file or key set. | 2 |

"Ours" means Cipherframe signed these statements. It does not prove that the objects were deleted
(only that Cipherframe says so, having listed storage empty) or that no one kept a copy.

## Anchoring (optional)

A signed manifest says what Cipherframe recorded, but its time is only as trustworthy as the
operator's clock. When an RFC 3161 Time-Stamping Authority is configured
(`CIPHERFRAME_TSA_URL`, [usage.md](usage.md#timestamp-anchoring-optional)), Cipherframe adds a
timestamp token from an independent party. It is off by default; a manifest without a token is
reported as "unanchored". Decisions: [ADR 0041](adr/0041-rfc-3161-anchoring-of-manifests.md).

**What is stamped.** SHA-256 of the DSSE `payload` bytes, the canonical manifest, not the envelope
or its stored JSON, so re-encoding by the database never changes it. The manifest commits to every
artifact through the Merkle roots, so one token anchors the whole asset. The request has a random
nonce and asks for the authority's certificate.

**When.** A `manifest.anchor` job is queued in the transaction that stores a manifest: when the asset
becomes ready, and again when the masked variant re-signs it (the old token goes with the old
manifest, and the new payload is stamped). The job calls the authority outside any transaction,
checks the answer (granted, the imprint and nonce are ours, the token signature verifies), and
stores the token, its time and the authority's URL only if the manifest is still the one it
stamped. A failure retries with backoff; after the last attempt the manifest stays unanchored and an
error is logged. Anchoring never delays or fails an asset.

**Fetching it.** `GET /v1/assets/{id}/manifest/timestamp` returns `token` (base64 DER), `gen_time`,
`tsa_url` and `imprint_sha256`, or `404 not_anchored` ([api.md](api.md#integrity-manifests-proofs-verify-adr-0033-0039)).

**Verifying it.** The token is checked offline, with the manifest envelope and the authority's CA:

```sh
curl -s -H "Authorization: Bearer $CF_KEY" https://api.example.com/v1/assets/$ASSET/manifest/timestamp -o ts.json
cipherframe verify --manifest manifest.json --keys keys.json --timestamp ts.json --tsa-ca tsa-ca.pem ./download/
```

The check requires that the token's imprint is SHA-256 of the envelope's payload, that the token
signature verifies, and that the signer's certificate chains to a trusted root with the
time-stamping usage, valid at the time in the token. It adds one line after the summary:
`anchored  <gen_time>  (<tsa>)`, `unanchored`, or `timestamp invalid (<reason>)`. An invalid
timestamp makes the exit code 2 (cannot say) and never turns a result into "modified"; without
`--timestamp` the output and exit codes are as before. The library is
`offline.VerifyTimestamp`.

**Trust anchors.** `--tsa-ca ca.pem` is a PEM bundle of the roots you trust for the authority;
without it the system roots are used. Get the CA certificate from the authority itself, out of
band: a token carries the signer's certificate, but only a root you obtained separately tells you
whom to believe. The verifier does not check certificate revocation.

**Privacy.** Only a 32-byte digest and a nonce leave your deployment. The authority never sees a
file, a name, a tenant or asset identifier, or the manifest itself, and it cannot tell what the
digest stands for. It does learn that you requested a timestamp at that moment.

## Verifying

The verifier needs **public keys only**: the manifest envelope (`GET /v1/assets/{id}/manifest`, or a
copy stored next to the files) and the published key set. It never calls Cipherframe, except for the
optional `--keys-url` fetch of the key set. The library is `internal/integrity/verify/offline`; the
tool is the static binary `cipherframe` (`CGO_ENABLED=0 go build ./cmd/cipherframe`).

```sh
# Every file under an HLS download that the manifest lists (paths are relative to that directory).
cipherframe verify --manifest manifest.json --keys keys.json ./download/
# The face-masked variant: its own directory, its own section of the manifest.
cipherframe verify --manifest manifest.json --keys keys.json --variant masked ./download-masked/
# One file, named by its manifest path, with the key set fetched over https.
cipherframe verify --manifest manifest.json --keys-url https://cipherframe.example/.well-known/cipherframe-keys.json \
  --path 720p/seg-0.m4s seg-0.m4s
# One file with an inclusion proof (GET /v1/assets/{id}/proof?path=...): the audit paths are checked
# up to the signed rendition and top-level roots.
cipherframe verify --manifest manifest.json --keys keys.json --proof proof.json seg-0.m4s
```

Output is one line per file, then a summary; `--json` prints the same as JSON:

```
ours        master.m3u8  (verified)
modified    720p/seg-1.m4s  (modified: sha256 9f..., the signed manifest records 3c...)
missing     480p/init.mp4  (missing)
9 ours, 1 modified, 0 cannot say, 1 missing
```

A file argument without `--path` is matched by its path relative to `--root` (default: as given;
an absolute path without `--root` uses its base name). A directory argument checks every file under
it that the manifest lists; manifest entries with no file are reported as `missing` (not modified,
and they make the exit code 2). Files in the directory that the manifest does not list are ignored.

**Exit codes:** 0 every file is ours; 1 at least one file is modified; 2 at least one cannot say or
is missing, and none modified; 3 usage error.

**Outcomes.** The five internal outcomes above, plus the precise reason, map onto three public ones:

| Public outcome | Reason shown | When |
| --- | --- | --- |
| ours | `verified` | The signature verified under a trusted key and the file's SHA-256 is the one the manifest records for the path (with `--proof`, also under the signed roots). |
| modified | `modified` | The signature verified under a trusted key, the path is in the manifest, and the file's hash differs: "a modified version of ours". |
| cannot say | `untrusted-key` | No signature is from a key in the key set. |
| cannot say | `tampered-envelope` | A trusted key id's signature does not verify. The envelope was altered or forged; that says nothing about the file, so it is never "modified". |
| cannot say | `malformed` | The envelope, key set, manifest or proof is not a valid document, or the proof does not belong to the manifest or its audit path is wrong. |
| cannot say | `unknown-path`, `no-variant` | The manifest has no such path, or no masked section. |
| cannot say | `cannot-say` | Anything else: an unreadable file, a failed or oversized `--keys-url` fetch. |

The signature is checked first, always. "Modified" is only ever claimed on the strength of a valid
signature by a trusted key. Active and retired keys are both trusted, so a record signed before a
rotation still verifies against the current published set; keys with another status or algorithm
are ignored. `--keys-url` must be https (plain http only for localhost), allows one GET with a
10-second timeout and 1 MiB, and is the only network access.

Not checked: file sizes (a matching SHA-256 makes them redundant), the timestamp unless `--timestamp` is given, and whether
a key set you fetched is the genuine one: pass a key set you obtained out of band when that matters.

## What this does not protect against

- A deletion record proves what Cipherframe deleted and that the key was destroyed. It cannot prove
  that nobody kept a plaintext copy.
- Without a timestamp authority, a record's time is only as trustworthy as the operator's clock. With one, the time is the authority's, but only for the manifest: a deletion record is not stamped.
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
