# 0031. Browser session creation and the JWT library

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M4-8; completes ADR 0029)
- Deciders: project owner

## Context

With the JWT and signed-callback providers (ADR 0029), the viewer's browser starts its own playback
session. If the embedding application's server started it, the application would use its API key.
That browser-facing endpoint needs a home, and JWT and JWKS handling needs a library.

## Options considered

- Endpoint: on edge, beside the other browser-facing routes; on api, beside `POST /v1/playback-sessions`.
- Library: go-jose v4; golang-jwt v5; lestrrat-go/jwx v3.

## Decision

- **`POST /v1/play/sessions` on the edge role.** The api role stays server-to-server only and can
  live on a private network. Edge reads each tenant's provider configuration (cached like the
  playback settings) and makes the outbound JWKS and callback requests, with the SSRF guards in
  ADR 0029. The tenant is managed through the api role's admin endpoints.
- **`github.com/go-jose/go-jose/v4`** (Apache-2.0) verifies JWTs and parses JWKS. Its parse
  functions take an explicit algorithm allowlist, so `alg: none` and algorithm confusion are ruled
  out by the API itself. Cipherframe adds the JWKS fetching, caching and SSRF checks itself.

## Consequences

- Edge gains outbound HTTPS, but only for tenants that configure a JWKS URL or a callback.
- Edge then serves every browser-facing playback call: create, playlists, key, heartbeat and end.
- A new dependency is added; go-licenses and govulncheck cover it.
