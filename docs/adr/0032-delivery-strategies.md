# 0032. Delivery strategies

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M4-5)
- Deciders: implementer, under the owner's standing approval for M4 (flagged for owner review)

## Context

M4-5 asks for two delivery strategies: `proxy`, where segments go through edge, and `presigned`,
where playlists point at short-lived storage URLs. A presigned URL is itself a credential, and
putting it in a playlist conflicts with pitfall 9 in the same way that tokens in URLs did (ADR 0030).

## Decision

The same shape as ADR 0030: a safe default, and an opt-in per tenant.

- **`proxy` is the default.** Segments are served by edge after the token check (M4-3).
- **`presigned`** is a tenant setting (`delivery`, either `proxy` or `presigned`). With it, edge
  writes presigned GET URLs for the delivery bucket into the session's media playlists, for the
  init segment and each media segment.
  - A URL expires at the token's expiry or after 10 minutes, whichever comes first, and is renewed
    whenever the player fetches the playlist again.
  - Playlists and keys still go through edge, so revocation still applies at the key endpoint.
  - Presigned URLs are never logged.
- Segments are ciphertext either way, so `presigned` exposes only encrypted bytes, and only until
  the URL expires.

## Consequences

- `presigned` takes segment traffic off edge, and storage or a CDN serves the bytes directly.
- With `presigned`, signed storage URLs appear in playlists, browser history and the logs of
  intermediaries. The docs say so, as they do for `token_in_url`.
- The source bucket is never presigned (I4). Only delivery objects are.
