# 0065. CDN implementation choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-23
- Gate: none (M10-1; choices [ADR 0062](0062-cdn-signed-urls.md) left open)
- Deciders: implementer

## Context

ADR 0062 decided the providers, the `cdn` delivery setting, the presigned expiry rule and a purge on
deletion. It did not say how the URLs are built, where the configuration is read, which role runs
the purge, how the purge is called, or what happens when settings and configuration disagree.

## Decision

**Signing, stdlib only.** `internal/cdn` has a `Signer` interface (`Sign(key, expires)`), one
implementation per provider, and no SDK.

- CloudFront: canned policy with the exact URL and `AWS:EpochTime`, RSA-SHA1 (PKCS#1 v1.5, the only
  scheme CloudFront defines) and CloudFront's URL-safe base64 (`+` to `-`, `=` to `_`, `/` to `~`).
  The key is a PEM file, PKCS#1 or PKCS#8, RSA of at least 2048 bits.
- Cloud CDN: `URL?Expires=...&KeyName=...` signed with HMAC-SHA1 under the 16-byte key, appended as
  URL-safe base64 with padding. The key file holds the key as Cloud CDN shows it (padded or not,
  trailing newline ignored).
- Object keys are checked against `[A-Za-z0-9._/-]` with no `..` before signing, so no URL needs
  escaping and the signed text is exactly what the player requests. Cipherframe's own keys always
  match; anything else is refused.
- The CDN URL is the base URL plus the object key, so the CDN's origin must be the delivery bucket
  root. Both Terraform examples do this. The base URL has no path.

**Configuration.**

- `CIPHERFRAME_CDN_PROVIDER`, `_BASE_URL`, `_KEY_ID`, `_SIGNING_KEY_FILE` as in the brief, plus what
  the purge needs: `CIPHERFRAME_CDN_CLOUDFRONT_DISTRIBUTION_ID`, or `CIPHERFRAME_CDN_CLOUDCDN_PROJECT`
  and `CIPHERFRAME_CDN_CLOUDCDN_URL_MAP`. They are required with the provider, because the purge is part
  of the decision. Any CDN variable without a provider is an error, and so is a literal
  `CIPHERFRAME_CDN_SIGNING_KEY`: there is no variable for the key itself, and the message says to use
  the file.
- The configuration loader validates the variables for every role. It does **not** read the key
  file, and does not require the path either: only the edge role signs, so only the edge reads and
  parses the key, at startup, and refuses to start with a message that names the setting and never
  the key. The api and worker roles need
  no key mounted. Helm users list `CIPHERFRAME_CDN_SIGNING_KEY` under `edge.secrets`, which the chart turns into
  `CIPHERFRAME_CDN_SIGNING_KEY_FILE` (the literal variable itself is never set).
- `base_url` must be `https` (`http` in development) and a bare origin.

**Purge runs on the worker.** ADR 0062 says the purge is a retried job after deletion. Deletion is
the worker's `asset.delete` job, so the CDN purge is the worker's job too, and the worker role gets
the invalidation permission (not the api or edge role). It needs the CDN settings, not the key.

- The `asset.cdn_purge` job is inserted inside the transaction that writes the deletion tombstone
  (`Repos.PgxTx` hands the River insert the same transaction), so it exists exactly when the
  deletion completed and cannot be lost between the two. Deletion does not wait for it.
- Arguments are tenant and asset IDs only. The prefix is `keys.DeliveryPrefix`, purged as
  `/t/<tenant>/a/<asset>/*`.
- Ten attempts with the default backoff (about an hour and a half in total). The last failed attempt writes
  `asset.cdn_purge_failed`; success writes `asset.cdn_purged`, both to the audit log with the asset
  as target. A retried job leaves one row. After a final failure cached ciphertext expires on its own
  and the key is already destroyed.
- Without a CDN configured on the worker nothing is queued, so a deployment that adds a CDN must
  configure the worker with it at the same time.

**Cloud CDN purge by REST, not the compute client.** The purger POSTs to
`compute/v1/projects/{p}/global/urlMaps/{m}/invalidateCache` with the client from
`golang.org/x/oauth2/google` (Application Default Credentials). `cloud.google.com/go/compute` is a
very large module for one call; `golang.org/x/oauth2` was already an indirect dependency and is now a
direct one. The purger takes an `*http.Client` and an endpoint, so tests run against `httptest`. The
call is asynchronous on Google's side; an accepted request counts as success. Cloud CDN limits how
often invalidations may run, which the retry backoff absorbs.

**CloudFront purge** uses `aws-sdk-go-v2/service/cloudfront` (new module, same family as the S3 and
KMS modules), with a caller reference derived from the prefix so a retry returns the existing
invalidation instead of creating another. The client is built for `us-east-1`, where CloudFront's API
is signed. It uses the default credential chain (the worker's role).

**Behaviour choices.**

- A tenant whose `delivery` is `cdn` while the deployment has no signer (the operator removed the
  CDN) is served as `proxy`. Playlists and keys stay correct and nothing breaks; the alternative, an
  error on every playlist, is worse. Setting `cdn` is refused with a field error on `delivery`
  (HTTP 400, `invalid_request`) when the api role has no CDN configured.
- Thumbnails stay on edge, as with `presigned`: they are unencrypted images.
- The expiry rule is the presigned code path, shared: `min(token expiry - now, 10 minutes)` in whole
  seconds, `401` when under a second is left.
- The end-to-end secret scan also looks for `Signature=`, `Key-Pair-Id=` and `KeyName=`.
- Migration 00030 widens the `delivery` check constraint to `cdn`.

**Terraform.** `enable_cdn` (default false) in both examples.

- AWS: distribution with origin access control onto the delivery bucket only, a trusted key group
  with the public key passed as `cdn_public_key_pem`, HTTPS only, the default `cloudfront.net` domain
  (a custom domain is left to the operator), CORS from `cors_allowed_origins`, and
  `cloudfront:CreateInvalidation` on that distribution for the worker role. With a customer-managed
  bucket key (`bucket_kms_key_arn`) the key policy must also allow CloudFront; the README says so.
- GCP: backend bucket (`CACHE_ALL_STATIC`, signed URLs), the signing key as a sensitive variable,
  a global external HTTPS load balancer with a Google-managed certificate for `cdn_domain`, the
  Cloud CDN service agent as reader of the delivery bucket (which keeps public access prevention),
  and a custom role with `compute.urlMaps.invalidateCache` bound to the worker service account at the
  project, because a URL map has no IAM policy of its own. The Cloud CDN key value is kept in
  Terraform state; the variable is marked sensitive and the README offers creating the key outside
  Terraform. With `cors_allowed_origins` set the backend bucket answers `Access-Control-Allow-Origin: *`:
  a backend bucket cannot vary the header per origin, the bytes are ciphertext and the URL is the
  credential.
- `terraform fmt -check` and `terraform validate` pass for both examples (checked with Terraform 1.12
  in a container; CI pins 1.17.2). Nothing was applied: no cloud account was used.

## Consequences

- The signing and purge code is tested with known answers, fakes and `httptest`; no test calls a
  cloud. The real CloudFront and Cloud CDN behaviour (policy acceptance, invalidation quotas, OAC and
  CORS settings) is **not** verified against live services in this change.
- The CloudFront known-answer check recomputes the canned policy and verifies the RSA signature with
  the public key rather than comparing against a fixed vector, because the test generates its own key
  (no private key literal in the repository). The Cloud CDN signature is a fixed vector computed
  outside Go with `openssl`.
- Adding the CloudFront SDK module adds one direct dependency; `golang.org/x/oauth2` becomes direct.
