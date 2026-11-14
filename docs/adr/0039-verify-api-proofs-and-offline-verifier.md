# 0039. Verify API, proofs and the offline verifier

- Status: Accepted (flagged for owner review before v1.0.0)
- Date: 2026-11-14
- Gate: none (surface of M5-3 and M5-4; the cryptography is ADR 0033)
- Deciders: project owner (delegated: accepted to keep the build moving)

## Context

ADR 0033 fixed hashing, trees, canonical JSON, DSSE and the signing keys, and M5-1 and M5-2 built
the signed manifest and the published key set. M5-3 needs an API that serves manifests and
inclusion proofs and answers "is this ours?", and M5-4 needs a verifier that works with public keys
only. ADR 0006 keeps every Go package under `internal/` until the v2 SDKs, and the `cipherframe`
CLI is M8-1.

## Options considered

1. **Manifests public**, proofs public, verify public: anyone holding a segment can check it, but
   it reveals asset existence, tenant ids and encoder details to anyone who guesses an id.
2. **Authenticated (`assets:read`)** for manifests, proofs and verify; the key set stays public. The
   embedding application fetches the manifest and proof and hands them to whoever must verify; the
   offline verifier then needs no Cipherframe access at all.
3. **A separate public "verification link"** per asset: a later, opt-in feature.

For the verifier: a public `pkg/` library now (contradicts ADR 0006), or the library stays under
`internal/integrity/verify` and ships as a CLI now, with the public Go API arriving in the v2 SDK.

## Decision

Option 2, and the CLI now.

**API (M5-3), all `assets:read`, tenant-scoped, RFC 9457 errors:**

- `GET /v1/assets/{asset_id}/manifest` returns the stored DSSE envelope as is (JSON), with
  `Content-Type: application/vnd.cipherframe.manifest+json; profile=dsse`. 404 until the asset is
  ready. The envelope's payload is the manifest, including the `masked` section when present.
- `GET /v1/assets/{asset_id}/proof?path=<path>[&variant=original|masked]` returns an inclusion
  proof for one artifact, identified by its manifest `path` (relative to the variant's HLS prefix):
  `{asset_id, variant, path, sha256, size, leaf_index, tree_size, rendition, rendition_root,
  audit_path[], top_level: {leaf_index, tree_size, audit_path[], root}}`. For an init or media
  segment the first level proves the leaf in its rendition tree and the second proves the rendition
  root in the top-level tree; for a playlist only the top-level level is present. Hashes are
  lowercase hex. Unknown path → 404 `artifact_not_found`. The proof is computed from the stored
  manifest (not from storage), so it is what the signature covers.
- `POST /v1/verify` with `{asset_id, path, sha256, variant?}` answers with `outcome`:
  `ours` (the path is in the signed manifest and the hash matches; the response includes the proof),
  `modified` (the path is in the manifest but the hash differs: "a modified version of ours"), or
  `cannot_say` (no such asset or path for this tenant, or the asset is not ready). With only
  `{sha256}` it looks the hash up among the tenant's registered artifacts: `ours` plus where it
  belongs, or `cannot_say` (a hash alone can never prove "modified"). The server never fetches or
  accepts file bytes; callers hash locally.

**Offline verifier (M5-4):**

- Library: `internal/integrity/verify/offline` (a subpackage, because `proof` imports `verify`)
  provides `VerifyArtifact(envelope, keys, path, data or sha256, variant)` and
  `VerifyProof(envelope, keys, proof, data or sha256)`, both needing only the public
  key set (`/.well-known/cipherframe-keys.json` JSON). They map the five internal outcomes of
  docs/integrity.md onto the three public ones: verified → **ours**; tampered with a valid trusted
  signature but a hash or path mismatch → **modified**; everything else (untrusted key, malformed,
  bad signature, unknown path, errors) → **cannot say**, with the precise internal reason shown.
- CLI: a new binary `cmd/cipherframe` with one subcommand now, `cipherframe verify`, which M8-1
  extends into the full CLI. It is a static binary with no server dependencies:
  `cipherframe verify --manifest m.json --keys keys.json [--variant masked] <file>...` where each
  file is matched to the manifest by `--path` or by its relative path in an HLS download; or
  `--proof p.json <file>` for a single artifact. Exit codes: 0 ours, 1 modified, 2 cannot say,
  3 usage error. `--keys-url` may fetch the key set over HTTPS; nothing else touches the network.

## Consequences

- Verification needs no secret and, offline, no Cipherframe access: the application exports the
  manifest (and optionally a proof) next to the files.
- Nobody can probe asset existence without an API key. A public verification link remains possible
  later as an explicit opt-in.
- The three-outcome mapping never reports "modified" on an error or an unknown key, matching the
  rule in docs/integrity.md.
- Timestamps (M5-5) attach to the envelope later; the verifier then also reports "anchored at" or
  "unanchored".
