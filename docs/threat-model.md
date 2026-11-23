# Threat model

> Status: reviewed in M9-5 against everything built through M8, plus the metrics endpoint and
> tracing from M9-1a (ADR 0053, ADR 0055). The first table is the original list; the sections after it cover what was added later.
> Known follow-ups are in [roadmap.md](roadmap.md#follow-ups). For backups and key loss, see
> [disaster-recovery.md](disaster-recovery.md).

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
| Token replay or sharing | Short TTL, scope-limited tokens, bounded replay at the key endpoint (per-token and per-session limits kept in Postgres), anomaly events `key_replay` and `key_rate` (ADR 0028), with optional auto-revoke. |
| Scripted scraping of a valid session | Anomaly signals: `key_replay`, `key_rate`, `session_limit`, `rapid_session_creation`, `segments_without_key`, each an event you can read and, per tenant and per kind, a revocation (default off). Catches a client that behaves unlike a player; see [what the anomaly signals catch and miss](#what-the-anomaly-signals-catch-and-miss). |
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

## What the anomaly signals catch and miss

The signals ([api.md](api.md#anomaly-signals-m4-9)) are tripwires for **clumsy** automation. They are cheap,
counted from data Cipherframe already has (invariant I10), and tunable per tenant.

They catch:

- a client that asks for the key over and over, with one token (`key_replay`) or one session (`key_rate`);
- a client that starts sessions faster than a person does (`rapid_session_creation`), and one that
  keeps trying after the viewer limit (`session_limit`, information only);
- a client that downloads segments without ever fetching the key (`segments_without_key`), which is
  what a script that only mirrors the ciphertext looks like.

They do **not** catch, and the tenant should assume they will not:

- a careful scraper that fetches the key like a player, paces its segment requests, heartbeats on time
  and uses one session per viewer ID. Every counter it moves stays under the defaults;
- a viewer who fetches the key once and shares the 16 bytes with someone else, or who saves the
  decrypted media: HLS with AES-128 is **not DRM** (I8). Whoever receives the key and the segments can
  decrypt them, and nothing here changes that;
- anything in `presigned` delivery that depends on counting segments: storage serves the segments, so
  `segments_without_key` never fires;
- a scraper that rotates viewer IDs. The viewer-level signals count per `viewer_id`, which the embedding
  application chooses;
- anything between the 30-second segment-count flushes: `segments_without_key` is detected about half a
  minute late, and a crash of an edge process loses the counts of that interval (the signal then fires
  later or not at all, never wrongly).

False positives are possible (a player that is slow to fetch the key, a shared household login, a test
rig), which is why the signals only record an event unless the tenant opts a kind into auto-revoke. A
failure of Cipherframe's own database or settings lookup never revokes anything (I11).

## Features added since the initial list (M9-5 review)

Each subsection names the assets, the threats (STRIDE letters: S spoofing, T tampering, R repudiation,
I information disclosure, D denial of service, E elevation of privilege), what mitigates them and
what is left over. "Residual" is what a deployer should still plan for.

### Integrity manifests, signing keys and anchoring (M5, ADR 0033, 0039, 0041)

- **Assets:** the manifest and deletion-record signing keys, the signed manifests and records, the
  published key set, RFC 3161 tokens.
- **Threats:** forged or altered record (S, T); stolen signing key (E); a verifier tricked into "ours"
  by an unknown key or a malformed envelope (S); a record denied later (R); key set tampered in
  transit (T); the authority returning a bad token (T); the anchoring job hammering a third party (D).
- **Mitigations:** Ed25519 over a canonical (JCS) DSSE payload, verified with public keys only
  ([integrity.md](integrity.md)); a malformed envelope, unknown key or unreachable key set is "cannot
  say", never "ours" or "modified"; seeds wrapped by the KMS with associated data that binds purpose,
  key id and algorithm (`internal/integrity`, `internal/signing`); the five-minute in-memory seed
  cache is zeroed on eviction; a token's imprint, nonce and signature are checked before it is stored
  and the verifier checks the chain at the token's own time (`internal/anchor`, ADR 0041); only a
  SHA-256 digest leaves the process, through `internal/outbound`; Merkle inclusion proofs per segment.
  The JCS, DSSE and Merkle parsers have fuzz targets from M5.
- **Residual:** a leaked or compromised key still verifies what it signed after retirement, because the
  key set has no "revoked as compromised" status (a follow-up). The key set is only as trustworthy
  as the channel that serves it: keep a pinned copy. Tracks and thumbnails sit outside the top-level
  Merkle root (ADR 0044). Anchoring depends on the authority you choose and is off by default.

### Face-masked variant and the ML masker (ADR 0036, 0037, 0038)

- **Assets:** the plaintext source and masked intermediate on the worker's disk, the masker's database
  role, the model file, the `external_tasks` hand-off table.
- **Threats:** masker output replaced or poisoned (T); the masker reading more than it needs (I); a
  hostile source crafted to crash or exhaust the decoder (D); a poisoned model file (T, E); a missed
  face treated as a guarantee (I).
- **Mitigations:** the hand-off payload names files relative to the job directory and holds no object
  key or URL; the masker claims tasks with its own database role and shares only the job's 0700 work
  directory with the Go worker (`ml/`); FFmpeg and the media probe run under the pipeline's limits
  (ADR 0025, 0027); the YuNet model file is pinned by SHA-256; the masked variant has its own content
  key, so one variant's key never opens the other, and a session is bound to one variant (token claim
  `v`, `internal/playback/token`).
- **Residual:** masking is best effort. Detection can miss a face (it is tuned for recall at a 0.6
  threshold, ADR 0036) and the masked variant is published even with `faces_detected: 0`. It does not
  hide voices, names on screen or a body. The masker and the worker must run on the same trusted
  node, and a compromised masker can read plaintext frames. It is not a redaction guarantee.

### CDN delivery (M10-1, ADR 0062, 0065)

With the tenant setting `delivery = cdn`, media playlists carry signed URLs of a CDN instead of
edge URLs. What this changes, stated plainly:

- **Revocation is not immediate for segments.** After a session is revoked, a signed URL it already
  received still fetches ciphertext from the CDN until the URL expires, at most 10 minutes (sooner
  if the token expires sooner). The key endpoint stays on edge and refuses a revoked session, so the
  bytes cannot be decrypted without a key the viewer already holds. A viewer who kept the key can
  decrypt what they fetched in that window, as in every mode (I8).
- **Cached ciphertext outlives deletion for a while.** Deletion destroys the content key and the
  objects first, then queues a purge (CloudFront invalidation or Cloud CDN cache invalidation) that
  deletion does not wait for. Until the purge completes, or the entry expires if every purge attempt
  fails, the CDN may still serve the old ciphertext. With the key destroyed those bytes are
  unreadable. The outcome of the purge is in the audit log.
- **A signed URL is a bearer credential** for its object, until it expires. It appears in playlists,
  browser history and the logs of intermediaries and of the CDN itself. Edge never logs it (the
  end-to-end secret scan checks for the signature parameters). The CDN's own access logs are the
  operator's to configure and protect.
- **The signing key** (CloudFront private key, Cloud CDN key) lets its holder mint URLs for any
  delivery object until the key is rotated at the CDN; it still cannot decrypt anything. Only the edge
  role reads it. Rotating means adding a new key at the CDN and in the edge's key file, then removing
  the old one.
- The CDN reads only the delivery bucket, through origin access control (CloudFront) or the CDN's
  service agent (Cloud CDN). The source bucket is never behind it (I4). Thumbnails are never served
  through the CDN.

### Content-key re-key (M10-4, ADR 0068)

- **What it is for:** a content key that may have leaked. After a re-key, the segments the service
  stores and serves are encrypted under a new key, and the old key is destroyed; the leaked key no
  longer decrypts anything the service holds or serves from then on.
- **What it does not do, plainly:**
  - It does **not** help against plaintext a viewer already saved (screen capture, a decrypted
    download), and it does **not** take back a key a viewer already holds: that key still decrypts
    every copy of the old ciphertext, wherever the copy is (I8).
  - Ciphertext copied before the switch stays readable with the old key. That includes bucket
    versions and replicas, CDN caches until the purge completes or the entry expires, and database
    backups, which still hold the old wrapped content key until they age out. Re-keying and then
    restoring such a backup puts the old key back.
  - It does not re-encrypt the source upload (the source bucket holds the original, not under this
    key) and does not touch unencrypted objects: init segments, thumbnails, subtitles.
- **Threats:** a re-key that corrupts or loses media (T, D); a re-key started by someone who should
  not (E); playback under a key that no longer matches (D).
- **Mitigations:** the operation is explicit, scoped (`assets:write`), audited
  (`asset.rekey_requested`, `_completed`, `_failed`, with no key or object key) and limited to one at
  a time per asset; every stored segment is checked against the signed manifest before it is
  decrypted; the new objects are written beside the old and one transaction switches, so a crash
  leaves the asset playable under the old key; plaintext stays in memory, one segment at a time
  (ADR 0027); the manifest is signed and (when configured) timestamped again.
- **Residual:** viewers mid-playback at the switch lose their session and must start again; both
  generations occupy storage until the job ends.

### Deletion and retention (M6, ADR 0040, 0042)

- **Assets:** the deletion record, the purge job, the time-to-live setting, the access-trail window.
- **Threats:** data survives deletion (I); a deletion record forged or skipped (R); a tenant deletes
  another tenant's asset (E); a purge that stalls and leaves an asset half-deleted (D); a restored
  backup brings deleted data back (I).
- **Mitigations:** the `deleting` state refuses new sessions and revokes live ones; objects are
  enumerated and removed, listed again to confirm they are gone, and the content keys are destroyed;
  the signed record counts the objects (`internal/purge`, I5, I6); tenant isolation on every query;
  retention queues the same deletion.
- **Residual:** crypto-shredding cannot reach plaintext a viewer saved. **A database backup still
  holds the wrapped key of an asset deleted after it, and a bucket copy still holds its
  ciphertext;** restoring both undoes the deletion ([disaster-recovery.md](disaster-recovery.md)).
  `audit_events` and `playback_sessions` have no retention window yet, and a permanently failing
  `asset.delete` leaves the asset `deleting` (roadmap follow-ups).

### Subtitles, thumbnails, branding (M7, ADR 0044, 0046, 0049)

- **Assets:** uploaded or imported subtitle files, the thumbnail sprite and track, the brand logo,
  the player pages that render cue text.
- **Threats:** markup or script injected through a cue or a track label, a cue that forges another
  cue or a playlist line (T, I); an oversized or hostile file (D); a crafted PNG that attacks the
  FFmpeg decoder (E, D); EXIF data or a file name that leaks personal data (I); attribute injection
  into the master playlist through a label or language (T).
- **Mitigations:** the strict parser and sanitizer (`internal/subtitles/parse.go`, `sanitize.go`)
  cap bytes, cues, lines and label length, require UTF-8 and no NUL, reduce markup to an allowlist
  and refuse a cue that would split into two; playlist attributes are built by hand and cannot hold
  a quote or a line break (`internal/hls/subtitles.go`); the logo is size-checked, decoded with Go's
  `image/png`, re-encoded, and FFmpeg receives raw pixels, never the uploaded bytes (ADR 0049); no
  file name is read; sprite and track are plaintext derived from plaintext and follow the
  job-directory rule.
- **Residual:** cue text is still text a viewer's player renders, so the player must never insert it
  as markup (the reference player does not). Subtitles and thumbnails are personal data; thumbnails
  of the original variant show unmasked faces, and subtitle words are shared by both variants. A
  burned-in logo can be cropped out by a determined viewer.

### Webhooks (M7-5, ADR 0045)

- **Assets:** endpoint secrets, the outbox rows, tenant endpoint URLs.
- **Threats:** SSRF through a tenant-chosen URL (I, E); a forged delivery (S); replay of a delivery
  (S); a secret in a log or a response (I); a slow or hostile receiver exhausting the dispatcher (D);
  an event reaching the wrong tenant (I).
- **Mitigations:** the single outbound client of ADR 0029 and 0031 (https only, the dialed address is
  checked after DNS, no redirects, bounded time and size); Standard Webhooks HMAC signatures with a
  per-endpoint 32-byte secret wrapped by the KMS and shown once; a 24-hour two-signature window on
  rotation; events written by triggers in the transaction of the change and fanned out per tenant;
  bounded attempts with backoff; log lines carry IDs, not secrets (`internal/webhook`).
- **Residual:** delivery is at least once, so receivers must deduplicate on the event ID and check
  the timestamp. A key-provider outage pauses delivery. Webhook secrets are not re-wrapped by KEK
  rotation; rotate the secret instead ([disaster-recovery.md](disaster-recovery.md)).

### Quotas and rate limits (M7-6, ADR 0047)

- **Assets:** tenant and client usage counters, the request rate limit.
- **Threats:** one client exhausting storage or processing (D); a client slipping past a limit by
  racing creates (D, E); a tenant reading another's usage (I).
- **Mitigations:** limits are enforced at asset creation and again at commit, from the registries and
  under the asset row lock; the lower of tenant and client wins; the admin scope manages them; a
  per-instance request rate limit.
- **Residual:** quotas are unlimited by default. Delivery bytes created during processing are not
  checked until commit. The request rate limit is per instance, so the effective limit grows with the
  number of instances (follow-up: share it). Rate limit at the ingress as well.

### Viewer authorization callback and JWT (ADR 0029, 0031)

Covered in the initial table. This review adds fuzz targets for the parsers that see a viewer's
request before authorization (playback token, bearer header, upload token, API key; see below).
**Residual:** the callback is not rate limited per tenant, and stored callback secrets are not
re-wrapped by KEK rotation (follow-ups).

### Overlay watermark (M7-3, ADR 0048)

- **Assets:** the overlay settings and the per-session code.
- **Threats:** removal of the overlay by the viewer (T); text injection through the template (T);
  a code that points at the wrong viewer (R).
- **Mitigations:** the overlay is drawn by the player, never burned in; the template is validated in
  the service and by database constraints (no markup characters, no unknown placeholder); the 40-bit
  session code maps to a session through `GET /v1/overlay-codes/{code}` and the access trail.
- **Residual: deterrence only.** Whoever controls the player, the page or a screen recorder removes
  it, and two sessions can share a code. Do not present it as proof of who leaked a recording. The
  invisible watermark that could do more is planned for v2.1.0.

### Command line tool and reference player (M8, ADR 0051, 0052)

- **Assets:** the API key and the upload and playback tokens on a user's machine and in the browser.
- **Threats:** a key in shell history or a process list (I); a server echoing a secret into output (I);
  a token sent to the wrong origin (I); a token in a URL, referrer or log (I); markup in cue text or
  labels rendered by the page (T, E); a playlist that points the player off-site (S).
- **Mitigations:** the CLI takes the key only from `CIPHERFRAME_API_KEY` or `--api-key-file`, scrubs
  the key and the upload token from every printed string and drops URLs from transport errors, and
  has no default server. The player sends the token only to the manifest's origin under the session
  directory (never to presigned storage), keeps it in memory, and stops on a 401 or 403. The
  rewriters emit only relative URIs under the session path, which the fuzz targets assert
  (`internal/hls/fuzz_test.go`).
- **Residual:** in URL-token mode (opt-in per tenant) the token appears in URLs and so in any log that
  records them. A host page that embeds the player owns its own XSS surface. A compromised
  workstation exposes the key.

### Metrics endpoint and OTLP export (M9-1a, ADR 0053, ADR 0055)

- **Assets:** operating figures, trace and metric attributes, the scrape bearer token, OTLP
  credentials.
- **Threats:** an unauthorized scrape of `/metrics` on the service's own port (I); a secret, session ID
  or object key leaking into a span, label or log line (I); high-cardinality labels exhausting the
  metrics store (D); tenant IDs reaching a third-party store (I).
- **Mitigations:** the endpoint is not mounted without `CIPHERFRAME_METRICS_TOKEN`; the token is
  read from the environment or a file, kept only as a digest, compared in constant time and never
  logged (`internal/telemetry/handler.go`); HTTP spans carry only the method, route template and
  status, never the URL, query, client address or headers (`internal/telemetry/http.go`, with a
  test on edge playback requests); no asset,
  session, client, viewer or key identifier is ever a label; the tenant label is opt-in. The end-to-end scan of
  spans and log lines for secret material comes with M9-1b.
- **Residual:** `/metrics` shares the public listener, so do not route it at the ingress. A leaked
  scrape token shows figures, not content or keys. With the tenant label on, tenant IDs reach the
  metrics store. OTLP carries whatever the collector may see: run it inside your network.
  An incoming `traceparent` header is honoured, so a client can choose the trace ID of its own
  requests; it cannot read or change anyone else's.

## Parser hardening: fuzz tests (M9-5)

Native Go fuzz targets run in every `go test` (seed corpus only) and with `go test -fuzz`. CI runs
each for about 20 seconds on pushes to `main` (the `fuzz` job in `.github/workflows/ci.yml`).

| Parser (attacker-controlled input) | Target | Property asserted |
|---|---|---|
| Session playlist rewriting | `internal/hls`: `FuzzRewriteMaster`, `FuzzRewriteMedia`, `FuzzRewrite` | no panic; every emitted URI is a relative name under the session path, optionally with the escaped token query; no query without a token; the output is still a valid playlist |
| Subtitle attributes in the master | `internal/hls`: `FuzzAddSubtitles` | a label or language never adds or breaks an attribute; the track URI stays allowed |
| Thumbnail track | `internal/hls`: `FuzzRewriteThumbnailTrack` | unchanged without a token; line count preserved |
| Playback token | `internal/playback/token`: `FuzzVerify`, `FuzzOpen`, `FuzzTamper` | only a token this keyring signed verifies; a flipped byte, expiry or another asset never verifies; every failure is one `ErrInvalid` |
| API key and bearer header | `internal/auth`: `FuzzParseKey`, `FuzzBearerToken` | accepted input is canonical; no whitespace in the token |
| Upload token | `internal/uploads`: `FuzzHashToken` | accepted input is canonical and hashes as SHA-256 |
| Subtitle files (WebVTT and SRT) | `internal/subtitles`: `FuzzParse` | no panic; accepted output has one timing line per cue, no blank-line run, no script tag, and parses again to the same bytes |
| Integrity (M5) | `jcs`, `dsse`, `merkle` | existing targets |

The tus `Upload-Metadata` header is parsed by the third-party tus library, not by Cipherframe, and
the service discards every client-supplied metadata value except the content type it set itself
(ADR 0040), so there is no Cipherframe parser to fuzz there.

## Out of scope

Cipherframe does **not** protect against:

- screen recording or camera capture of playback,
- any overlay or watermark acting as protection (it is deterrence only),
- a guarantee that every face in a recording is masked,
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

- A compromised worker process holds the current integrity signing key in memory (unwrapped for up to
  five minutes at a time) and can ask the key provider to unwrap it, so it can sign false manifests
  and deletion records until the key is rotated. Rotate the key (`POST /v1/signing-keys/rotate`) and
  retire the old one to stop new signatures; records the key already signed stay valid, and a
  retired key still verifies them, so a leaked key cannot be told apart from an honest retirement
  yet (ADR 0033). Run workers on dedicated nodes, and give edge and api processes no more KMS access
  than they need.

- While a transcode runs, plaintext segments exist on the worker's local disk in a private 0700
  directory (ADR 0027). Anyone with root on that node can read them; run workers on dedicated nodes
  with encrypted local disks.

- Losing the key-encryption key makes every asset permanently unreadable. That is the same property
  that makes crypto-shredding work.
- Crypto-shredding cannot reach plaintext a viewer already saved.
