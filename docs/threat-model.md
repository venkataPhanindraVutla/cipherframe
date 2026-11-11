# Threat model

> Status: initial (M0-4). Completed in M9-5 once the design exists.

## Assets worth protecting

1. Source recordings (personal data).
2. Content keys and key-encryption keys.
3. Playback tokens and sessions.
4. Derived artifacts: subtitles, transcripts, thumbnails (faces), fingerprints.
5. Access logs (who watched what).
6. Signing keys for integrity manifests and deletion records.

## Actors

| Actor | Trust |
|---|---|
| Operator | Trusted to run the service and hold storage and KMS credentials. |
| Embedding application | Trusted to authorize viewers; authenticated by API key, JWT or signed callback (ADR 0009, ADR 0029). |
| Authorized viewer | Trusted to watch during a session; **not** trusted to stop there. |
| Unauthorized party | Untrusted; may hold leaked URLs, expired tokens or copied playlists. |
| Verifier | Untrusted; holds only public keys. |

## Threats in scope (initial list)

| Threat | Intended mitigation |
|---|---|
| Original fetched directly | Source bucket private; source key never returned (I4). |
| Segments fetched from storage without a session | Segments are AES-128 ciphertext; keys only via the session-checked key endpoint. |
| Revoked viewer keeps playing | Key endpoint checks session state on every request; revocation is immediate there. |
| Token replay or sharing | Short TTL, scope-limited tokens, bounded replay at the key endpoint (per-token and per-session limits kept in Postgres), anomaly events `key_replay` and `key_rate` (ADR 0028). |
| Edge process compromised | The edge role holds KMS access and the token signing keys, so a compromised edge process can unwrap the content keys of assets while they are played and mint tokens. Inherent to AES-128 HLS (I8). Run edge with the narrowest KMS permissions your provider allows and keep it apart from other roles. |
| Secrets in logs | Redacting logger; automated scan of a full playback run (pitfall 9). |
| Data survives "deletion" | Storage enumeration, key destruction, re-list, signed record (I5, I6). |
| Forged deletion or integrity record | Signatures verifiable with public keys only (pitfall 1); optional RFC 3161 timestamps. |
| KMS outage reported as success | Fail closed (I11). |
| SSRF through a tenant-chosen JWKS or callback URL | One outbound client (`internal/outbound`): https only, the dialed address is checked after DNS resolution on every attempt (loopback, private, link-local and cloud metadata, multicast, unspecified, CGNAT, special-purpose ranges, IPv4-mapped, NAT64 and 6to4 forms), no redirects, no environment proxy, bounded responses and time, errors without the URL (ADR 0029, 0031). |
| Forged or confused JWT (`alg: none`, HMAC with the public key, another key's algorithm) | The parser takes an allowlist (EdDSA, ES256, RS256); a key is used only with its registered algorithm; `iss`, `aud`, `exp` and a single-use `jti` are required (ADR 0029). |
| One JWT opening every asset of a tenant | An `asset_id` claim equal to the requested asset is required; `exp` is at most 24 hours ahead. |
| Replay of a JWT | `jti` is claimed in Postgres until `exp` plus the skew; exactly one concurrent use wins. |
| Signed callback abused or misconfigured | The callback fails closed: only HTTP 200 with a strict `{"allow": true, "viewer_id": "…"}` grants; a timeout (2 s), a redirect, any other status, a malformed or oversized answer or a network error denies; answers are never cached. Requests are signed (Standard Webhooks HMAC-SHA256) with a per-tenant secret kept only as a KMS envelope bound to tenant and version. Cipherframe's own failure to unwrap the secret is a `503`, not a denial (I11). |

## Out of scope

Cipherframe does **not** protect against:

- screen recording or camera capture of playback,
- an authorized viewer keeping a copy of what they were allowed to watch,
- scripted reassembly of segments while a session is valid,
- compromise of the operator's own storage or KMS credentials,
- any expectation that video "cannot be downloaded": HLS AES-128 is not DRM.

## Known hard limits

- The browser-session endpoint (`POST /v1/play/tenants/{tenant_id}/sessions`) is public until the JWT
  or the callback decides. A request that reaches a configured callback makes Cipherframe call the
  tenant's endpoint, so anyone who can reach edge can make a tenant's callback run; Cipherframe does not
  rate-limit callbacks per tenant. Put a rate limit in front of edge. JWKS fetches are limited to one
  per tenant every 30 seconds.
- A compromised edge process also holds the means to unwrap callback secrets (it needs them to sign), as
  it holds the playback token keys and KMS access for content keys.

- While a transcode runs, plaintext segments exist on the worker's local disk in a private 0700
  directory (ADR 0027). Anyone with root on that node can read them; run workers on dedicated nodes
  with encrypted local disks.

- Losing the key-encryption key makes every asset permanently unreadable. That is the same property
  that makes crypto-shredding work.
- Crypto-shredding cannot reach plaintext a viewer already saved.
