# 0030. Playback token transport

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M4-3; resolves a conflict between M4-3 and pitfall 9)
- Deciders: project owner

## Context

Every playlist, key and segment request must carry the playback token (pitfall 5, ADR 0028). M4-3
says the session-scoped manifest rewrites playlist URIs so that every request carries the token. But
pitfall 9 forbids tokens in URLs, because URLs end up in browser history, proxy and CDN logs, and
`Referer` headers. Players built on Media Source Extensions (hls.js, the reference player) can set
request headers. Native HLS in Safari on iOS cannot.

## Options considered

1. Header by default, with a per-tenant opt-in that puts the token in URLs for native players.
2. Header only.
3. Token in the URL path, always.

## Decision

Option 1.

- **Default:** the player sends `Authorization: Bearer <token>` on every request to edge.
  Session-scoped playlists contain only paths under the session (`/v1/play/<session_id>/...`) and
  never a token. The session ID alone grants nothing.
- **Opt-in fallback:** a tenant setting, `token_in_url` (off by default), makes edge put the token
  in each URI of the session-scoped playlists as the query parameter `t`, for native HLS players.
  When it is on:
  - edge accepts the token from the query parameter only on playback routes;
  - edge removes the parameter from anything it logs or traces (the access log records the session
    ID);
  - playback responses carry `Referrer-Policy: no-referrer`;
  - the documentation states that the token can then appear in browser history and in logs of
    proxies or CDNs that the operator does not control.
- A request that carries the token both ways is rejected.
- The key endpoint answers only `Authorization` requests unless `token_in_url` is on.

## Consequences

- Pitfall 9 holds by default. The leak path is opt-in, per tenant, and documented.
- The CORS policy must allow the `Authorization` header from the tenant's allowed origins.
- Tokens in URLs last at most the token TTL (10 minutes by default), and revocation still applies
  at the key endpoint.
