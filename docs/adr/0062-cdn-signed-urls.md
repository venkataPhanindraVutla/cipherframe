# 0062. CDN signed URLs

- Status: Accepted
- Date: 2026-11-23
- Gate: P16
- Deciders: project owner

## Context

M10-1 adds CDN delivery: segments are served by a CDN from short-lived signed URLs, with a documented
revocation limit (cached ciphertext stays fetchable until the URL expires; the key endpoint still
gates playback) and purge on deletion. ADR 0032 already has two delivery strategies, `proxy`
(default) and `presigned`. A signed URL is a credential, so pitfall 9 applies to it as it does to
presigned URLs. The M9 Terraform examples cover AWS and GCP.

## Options considered

- **Providers:** CloudFront and Cloud CDN; CloudFront only; CloudFront plus a generic HMAC URL
  token for other CDNs; moving CDN support to v1.1.
- **Expiry and purge:** the presigned rule (token expiry or 10 minutes, whichever is first) with a
  purge on deletion; 2 minutes with a purge; the presigned rule without a purge.

## Decision

**Providers: CloudFront and Cloud CDN**

- A third tenant delivery setting, `cdn`, next to `proxy` and `presigned`. The operator configures
  one CDN for the deployment: the provider (`cloudfront` or `cloudcdn`), the CDN base URL, the
  signing key ID or key name, and the signing key as a file (`_FILE` variable), never as a literal.
- CloudFront uses signed URLs with a canned policy and a key from a trusted key group. Cloud CDN uses
  its signed URL scheme with a named signing key.
- The CDN's origin is the delivery bucket only, reached privately (CloudFront origin access control;
  a Cloud CDN backend bucket). The source bucket is never behind the CDN (I4). The AWS and GCP
  Terraform examples gain an optional CDN.
- A tenant cannot choose `cdn` unless the deployment has a CDN configured; the settings endpoint
  says so.

**Expiry: the presigned rule**

- Edge writes signed CDN URLs for the init segment and each media segment into the session's media
  playlists. A URL expires at the playback token's expiry or after 10 minutes, whichever comes
  first, and is renewed whenever the player fetches the playlist again.
- Playlists and keys still go through edge, so revocation and session checks are unchanged.
- Signed URLs are never logged, never put in spans or metric labels, and the end-to-end secret scan
  (ADR 0058) covers them.

**Purge on deletion**

- Deleting an asset also sends a CDN purge for the asset's delivery prefix (a CloudFront
  invalidation; a Cloud CDN cache invalidation). The purge runs as a retried job after the objects
  and the content key are gone; deletion does not wait for it, and its outcome is recorded in the
  audit log.

## Consequences

- Revocation limit, stated plainly in the docs: after a session is revoked, a signed URL it already
  received still fetches ciphertext from the CDN until it expires (at most 10 minutes). Without the
  key, which the key endpoint refuses, those bytes cannot be decrypted.
- After deletion, cached ciphertext may still be served until the purge completes or the cache entry
  expires. The content key has been destroyed by then, so the bytes are unreadable.
- Signed CDN URLs appear in playlists, browser history and intermediary logs, as presigned URLs do
  (ADR 0032); the docs say so.
- Other CDNs (Cloudflare, Fastly, Bunny) are not supported in v1; `proxy` behind any CDN that does
  not cache authenticated responses remains possible.
