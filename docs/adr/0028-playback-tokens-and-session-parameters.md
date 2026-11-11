# 0028. Playback tokens and session parameters

- Status: Accepted
- Date: 2026-11-11
- Gate: P6
- Deciders: project owner

## Context

M4 serves session-scoped HLS to browsers. Every playlist, key and segment request carries a token
(pitfall 5). Segment requests must be checked without a database round trip. The key endpoint must
check the session row so that revocation applies at once (pitfall 12, I11). The plan leaves the token
format and the token, heartbeat, session, concurrency and replay parameters open.

## Options considered

- Token format: a compact HMAC token in Cipherframe's own format; PASETO v4.public (Ed25519); JWT
  pinned to EdDSA.
- Lifetimes: balanced (10 min / 60 s / 5 min / 4 h); strict (2 min / 30 s / 2 min / 2 h); relaxed
  (30 min / 5 min / 15 min / 12 h).
- Concurrency: 3 per viewer, reject the new one; 3, revoke the oldest; no limit by default.
- Key replay: 20 fetches per token and 30 a minute; 5 and 10; 100 and 60.

## Decision

**Token format**

- `v1.<payload>.<kid>.<mac>`, every part base64url without padding. The payload is compact JSON with
  the session ID, asset ID, scope (`manifest`, `key` or `segment`, or a set of them) and expiry. The
  MAC is HMAC-SHA256 over the version, payload and key ID.
- The signing secret comes from configuration (environment variable or `_FILE`), with key IDs, so it
  rotates the way the API-key pepper does (ADR 0016): new tokens use the current key, and older keys
  verify until their overlap ends.
- Edge checks segments and playlists statelessly (MAC, expiry, scope, asset). The key endpoint also
  checks that the session row is active.
- Tokens are never logged. Access logs record the session ID, never the token.

**Lifetimes** (defaults; each can be set per tenant)

- Token TTL 10 minutes.
- The player sends a heartbeat every 60 seconds, and each heartbeat returns a fresh token, so a link
  stays valid for the whole session.
- A session ends after 5 minutes without a heartbeat, and 4 hours after creation at most.

**Concurrency**

- At most 3 active sessions per viewer (tenant plus viewer ID). Creating a fourth fails with
  `409 session_limit`, and existing sessions are left alone. A tenant can change the limit, and 0
  means unlimited.

**Key endpoint replay bound**

- At most 20 key fetches per token, and at most 30 key requests a minute per session. Past either
  bound the request gets `429` and a `key_replay` anomaly event (M4-9) is raised.
- Responses are `Cache-Control: no-store`, with CORS restricted to the tenant's allowed origins.

## Consequences

- No new dependency, and no algorithm negotiation on the hot path.
- Anyone holding the HMAC secret can mint tokens, so api and edge must protect it like the pepper.
  Splitting signing from verification (PASETO public keys) is not part of v1.
- Revoking a session stops key fetches at once. Segments already fetched stay decryptable by anyone
  who holds the key: AES-128 HLS is not DRM (I8).
- Heartbeats add one small request a minute per viewer.
