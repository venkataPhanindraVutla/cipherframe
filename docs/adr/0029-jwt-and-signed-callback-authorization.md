# 0029. JWT and signed-callback authorization

- Status: Accepted
- Date: 2026-11-11
- Gate: P7 (JWT and signed callback)
- Deciders: project owner

## Context

ADR 0009 settled API keys for server-to-server calls. M4-8 adds two more ways for an embedding
application to authorize a viewer's playback session: a JWT the application issues, and a signed
callback in which Cipherframe asks the application. Both have to fail closed (I11).

## Options considered

- JWT keys: JWKS URL plus static keys; static keys only; JWKS URL only.
- Callback: a signed POST that fails closed with no caching; the same with a 30-second allow cache;
  deferring the callback to v1.1.

## Decision

**JWT provider** (configured per tenant)

- Keys come from an HTTPS JWKS URL, from public keys uploaded through the admin API, or from both.
- A JWKS document is cached for about 10 minutes. It is refetched when a token names an unknown
  `kid`, with refetches rate-limited. Fetches refuse private, loopback and link-local addresses
  (SSRF guard), redirects, and responses over a size limit.
- Algorithm allowlist: EdDSA, ES256 and RS256 (RSA keys of at least 2048 bits). `none` and HMAC
  algorithms are always rejected, and a key is only used with the algorithm it is registered for.
- `iss`, `aud`, `exp` and `jti` are required. Clock skew is at most 60 seconds. A `jti` creates at
  most one session; repeats are rejected until the token expires.

**Signed-callback provider** (configured per tenant)

- When a session is created, Cipherframe POSTs the asset ID, viewer ID, request ID and a timestamp
  to the tenant's HTTPS URL. The request is signed with HMAC-SHA256 over the timestamp and body, in
  the Standard Webhooks style, with a per-tenant secret that can be rotated.
- Timeout 2 seconds. Only an explicit allow in a well-formed response grants a session. A timeout,
  any non-2xx status, a malformed body or a network error denies it.
- Answers are not cached. The same SSRF guards as JWKS fetches apply.

## Consequences

- Outbound HTTPS from the api role is needed only for tenants that use JWKS URLs or callbacks.
- Every session creation through a callback waits on the tenant's endpoint (at most 2 seconds).
- Negative tests cover `alg: none`, HMAC algorithms, wrong audience, expiry, a replayed `jti`, an
  unknown `kid`, callback timeouts and bad callback signatures.
