# 0041. RFC 3161 anchoring of manifests

- Status: Accepted (flagged for owner review before v1.0.0)
- Date: 2026-11-14
- Gate: D7
- Deciders: project owner (delegated)

## Context

A signed manifest proves what Cipherframe recorded, but its time is only as trustworthy as the
operator's clock (ADR 0033). D7 makes RFC 3161 anchoring optional and off by default, and ADR 0034
recommends authorities without enabling any. M5-5 builds it. The questions were what exactly to
stamp, when, how to keep it from ever blocking an asset, which library to use, and how a verifier
checks the result offline.

## Options considered

- **What to stamp**: the DSSE envelope, the stored JSON, or the payload bytes. The stored envelope is
  jsonb, which Postgres re-encodes, so only the payload (the canonical manifest) is stable.
- **When**: inline in the completion transaction, or a job. A network call inside a transaction
  holds locks and makes a slow authority block the asset.
- **Library**: hand-written CMS and ASN.1, or `github.com/digitorus/timestamp` with its `pkcs7`
  dependency (BSD-2-Clause and MIT, both on the allowed list).

## Decision

1. **Off by default.** `CIPHERFRAME_TSA_URL` turns it on: https only, and http only when
   `CIPHERFRAME_ENV=development`, for a local authority. `CIPHERFRAME_TSA_TIMEOUT` (default 10s, at
   most 2m) bounds one request. `CIPHERFRAME_TSA_POLICY_OID` (optional, dotted decimal) asks for a
   policy. All three are validated when the configuration loads. Only the worker role uses them.
2. **What is stamped.** SHA-256 of the DSSE payload bytes (the canonical manifest), so storage
   re-encoding never changes the imprint. The request carries a random nonce and `certReq=true`.
   Only that digest leaves the process.
3. **When.** A River job `manifest.anchor` (default queue) is enqueued in the same transaction that
   stores a manifest: asset completion, and `CompleteMasking`, which re-signs with the masked
   section. The re-sign replaces the manifest row, so the old token is gone with it and a new job is
   enqueued. The job calls the authority outside any transaction and checks the response: status
   granted, imprint and nonce match, token signature valid (a token with no certificate is
   refused). It stores the token (DER), its generation time and the authority URL on
   `asset_manifests` only if the manifest still has the payload hash it stamped (a conditional
   `UPDATE`, new migration `00018`). A job whose manifest was re-signed meanwhile does nothing. It
   retries with River backoff (10 attempts); after the last one the manifest stays unanchored and
   an error is logged. Anchoring never blocks the asset, and the job's arguments are identifiers and
   the payload digest only.
4. **Library.** `github.com/digitorus/timestamp` and its `pkcs7` dependency. The licence check
   (`go-licenses`) passes. Trust is not decided in the job: the verifier checks the chain.
5. **API.** `GET /v1/assets/{asset_id}/manifest/timestamp` (`assets:read`) returns `{token (base64
   DER), gen_time, tsa_url, imprint_sha256}`, or `404 not_anchored` (new error code). The manifest
   endpoint is unchanged, byte for byte.
6. **Verifier.** A library function checks a token against an envelope: the imprint is SHA-256 of
   the payload, the token signature verifies, and the signer's certificate chains to the system
   roots or a supplied CA bundle with the time-stamping usage, checked at the token's own time.
   `cipherframe verify ... --timestamp ts.json [--tsa-ca ca.pem]` adds one line: `anchored
   <gen_time>  (<tsa>)`, `unanchored`, or `timestamp invalid (<reason>)`. An invalid timestamp
   makes the exit code 2 (cannot say) and never "modified"; without `--timestamp` nothing changes.

## Consequences

- An operator who configures an authority accepts its terms; ADR 0034 names options and enables
  none. The authority learns only that a digest existed at a time.
- The token stamps the manifest, and the manifest commits to every artifact, so one token anchors
  the whole asset. A masked re-sign needs its own token; there is briefly none for the new manifest.
- The job's request goes to an operator-set URL, so it does not use the tenant-facing SSRF guard of
  `internal/outbound` (which would refuse a private-network authority). It does refuse redirects,
  bounds the response to 1 MiB and the request to the configured timeout.
- Turning anchoring off while jobs are queued leaves those jobs failing until they are discarded;
  nothing else is affected.
- Not covered: certificate revocation (the verifier does not fetch CRLs or OCSP), timestamping the
  deletion record, and renewing tokens when an authority's certificate expires (archive timestamps).
