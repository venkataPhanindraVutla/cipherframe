# CDN delivery

With the tenant delivery setting `cdn`, media playlists carry signed URLs of a CDN (CloudFront or
Cloud CDN) for the init segment and every media segment, so the CDN serves the encrypted bytes and
edge does not. The decisions are in [ADR 0062](adr/0062-cdn-signed-urls.md) and
[ADR 0065](adr/0065-cdn-implementation.md). The default, `proxy`, is unchanged, and nothing here
applies until you configure a CDN.

## What stays on edge

Master and media playlists, the key endpoint, thumbnails and everything else. Only segments move.
Because the key endpoint still checks the session on every fetch, a revoked session cannot get a key.

## Revocation and deletion limits

- **Revocation.** A signed URL is a bearer credential until it expires, which is the playback token's
  expiry or 10 minutes, whichever comes first (the same rule as `presigned`; the player gets fresh
  URLs when it refetches the media playlist). After a session is revoked, URLs it already received keep
  fetching ciphertext from the CDN until they expire, at most 10 minutes. Without the key, which the
  key endpoint now refuses, the bytes cannot be decrypted.
- **Deletion.** Deleting an asset destroys its content keys and objects first. A purge job then
  removes the asset's delivery prefix from the CDN cache; deletion does not wait for it. Until the
  purge completes, or the entry expires if every attempt fails, the CDN may still serve the old
  ciphertext, which is unreadable because the key is gone.
- **Visibility.** Signed URLs appear in playlists, browser history, and the logs of intermediaries
  and of the CDN itself, as presigned URLs do. Edge never logs them.

## Operator configuration

| Variable | Notes |
| --- | --- |
| `CIPHERFRAME_CDN_PROVIDER` | `cloudfront` or `cloudcdn`. Unset means no CDN, and tenants cannot choose `cdn`. |
| `CIPHERFRAME_CDN_BASE_URL` | `https://host` of the CDN, no path. Its origin is the delivery bucket root. |
| `CIPHERFRAME_CDN_KEY_ID` | CloudFront public key ID, or Cloud CDN key name. |
| `CIPHERFRAME_CDN_SIGNING_KEY_FILE` | Path of the signing key. Edge only. There is no variable for the key itself. |
| `CIPHERFRAME_CDN_CLOUDFRONT_DISTRIBUTION_ID` | CloudFront: the distribution to invalidate. |
| `CIPHERFRAME_CDN_CLOUDCDN_PROJECT`, `CIPHERFRAME_CDN_CLOUDCDN_URL_MAP` | Cloud CDN: the URL map to invalidate. |

Give every role the settings (the api role refuses `cdn` without them, the worker purges) and the key
file to the **edge** role only. The edge refuses to start if it cannot read and parse the key; a
message names the setting, never the key. In the Helm chart, list the key under `edge.secrets` as
`CIPHERFRAME_CDN_SIGNING_KEY`; the chart sets `CIPHERFRAME_CDN_SIGNING_KEY_FILE` (see
`deploy/helm/cipherframe/ci/all-features-values.yaml`). Details of each variable:
[usage.md](usage.md#configuration).

A tenant then sets `delivery` to `cdn` ([api.md](api.md)). If the operator later
removes the CDN, such tenants are served as `proxy` until they change the setting.

## Setup: CloudFront

1. Create an RSA 2048 key pair: `openssl genrsa -out cdn-key.pem 2048`, and
   `openssl rsa -in cdn-key.pem -pubout -out cdn-pub.pem`.
2. Apply `deploy/terraform/aws` with `enable_cdn = true` and `cdn_public_key_pem` set to the public
   key. It creates the distribution (origin access control onto the delivery bucket only, trusted key
   group, HTTPS only) and lets the worker role create invalidations. Or build the same by hand: the
   source bucket must never be an origin.
3. Set `CIPHERFRAME_CDN_PROVIDER=cloudfront`, `_BASE_URL`, `_KEY_ID` and
   `_CLOUDFRONT_DISTRIBUTION_ID` from the Terraform outputs, and mount `cdn-key.pem` into the edge.
4. CORS: set `cors_allowed_origins` so the distribution answers your players' origins.

URLs use a canned policy (the exact URL and an expiry), RSA-SHA1 as CloudFront defines it.

## Setup: Cloud CDN

1. Generate a key: `head -c 16 /dev/urandom | base64 | tr +/ -_`.
2. Apply `deploy/terraform/gcp` with `enable_cdn = true`, `cdn_domain` and `cdn_signing_key_value`
   (or add the key with `gcloud compute backend-buckets add-signed-url-key`). It creates the backend
   bucket, load balancer and certificate, and a custom role with `compute.urlMaps.invalidateCache` for
   the worker. Point the domain's DNS at `cdn_ip_address`.
3. Set `CIPHERFRAME_CDN_PROVIDER=cloudcdn`, `_BASE_URL`, `_KEY_ID`, `_CLOUDCDN_PROJECT` and
   `_CLOUDCDN_URL_MAP`, and write the key to the file the edge reads. The worker uses Application
   Default Credentials (Workload Identity on GKE).

URLs carry `Expires`, `KeyName` and an HMAC-SHA1 `Signature`, as Cloud CDN defines.

## Purge behaviour

When an asset's deletion completes, the same database transaction queues an `asset.cdn_purge` job
(identifiers only). The worker runs it: a CloudFront invalidation of `/t/<tenant>/a/<asset>/*`, or a
Cloud CDN `invalidateCache` with that path prefix. It retries with backoff for up to ten attempts.
The audit log gets `asset.cdn_purged` when the CDN accepted the request, or `asset.cdn_purge_failed`
after the last failed attempt (`GET /v1/audit-events`, `cipherframe audit export`). Both providers run
invalidations asynchronously and limit how many you may make, so a purge can take minutes to finish
at the edge. If a purge ends in failure, the cached ciphertext expires on its own and no key exists.
A deployment without a CDN configured on the worker queues no purge, so add the CDN settings to
the worker at the same time as to the edge.

## What is not verified

The signing and purge code is tested with known answers, fakes and a local test server. It was not
run against live CloudFront or Cloud CDN, and the Terraform examples were validated, never applied.
Try a playback and a deletion in a test account first.
