# Cipherframe on AWS (Terraform example)

An example, not a turnkey stack. It creates the storage and key resources a Cipherframe deployment
needs on AWS. The project never applies it from CI: CI only runs `terraform fmt -check`,
`init -backend=false` and `validate`, with no credentials (ADR 0054, ADR 0056). Read the plan before
you apply it to a real account.

## What it creates

- Two S3 buckets, `source` (uploaded originals) and `delivery` (encrypted HLS, subtitles, brand
  logos). Both block all public access, enforce bucket-owner object ownership, deny non-TLS requests
  and use server-side encryption (SSE-S3 by default, SSE-KMS with `bucket_kms_key_arn`).
  Versioning is off by default (`bucket_versioning`). There is no expiry lifecycle, because purge
  deletes explicitly (ADR 0042); the only optional rule aborts unfinished multipart uploads in the
  source bucket (`abort_incomplete_multipart_days`).
- One AWS KMS key for the Cipherframe KEK (symmetric, automatic rotation on) and the alias
  `alias/<name_prefix>-kek`. The key policy grants use only to the IAM roles below.
- Three IAM roles, `<name_prefix>-api`, `-edge` and `-worker`, each with one inline policy.
  Their trust policies are an input (`assume_role_policies`), not hard-coded.

## Role to permission table

Derived from the code (`internal/storage/keys` for the layout, `internal/uploads`, `internal/branding`,
`internal/subtitles`, `internal/purge`, `internal/pipeline`, `internal/edge` for the calls,
`internal/health` for the readiness probe, `internal/contentkey`, `internal/signing`,
`internal/viewerauth` and `internal/webhook` for the key calls).

| Role | Source bucket, `t/*/a/*/source/*` | Delivery bucket | KMS (KEK) |
| --- | --- | --- | --- |
| `api` | `PutObject` (presigned PUT and part URLs, multipart create, complete), `GetObject` (HEAD to check the upload), `DeleteObject`, `AbortMultipartUpload` | `PutObject`, `DeleteObject` on `t/*/a/*/subtitles/*` and `t/*/branding/logo/*` | `Encrypt`, `Decrypt`, `DescribeKey` |
| `edge` | `PutObject`, `GetObject`, `DeleteObject`, `AbortMultipartUpload`, `ListMultipartUploadParts` (part uploads and tus, which keeps a `.info` object beside the upload) | `GetObject` on `t/*/a/*` (playlists, segments, subtitles, thumbnails, and presigned GET URLs) | `Decrypt` only |
| `worker` | `GetObject` (fetch the original), `DeleteObject`, `AbortMultipartUpload` (purge) | `PutObject`, `GetObject` (brand logo), `DeleteObject` on `t/*` (publish, cleanup, purge) | `Encrypt`, `Decrypt`, `DescribeKey` |
| every role | `GetObject` on `_cipherframe/readiness-probe`, `ListBucket` on the bucket | the same | none |

Notes on the derivation:

- Every server process checks both buckets at readiness with a HEAD of `_cipherframe/readiness-probe`
  (a key nothing writes). S3 answers 404 only to a caller who may list the bucket, otherwise 403,
  which would keep the role unready. That is why `s3:ListBucket` and `GetObject` on that one key are
  granted to all three roles. `ListBucket` also covers the prefix listings that deletion and purge do.
- `edge` has no write access to the delivery bucket and `api` has no read access to delivered
  media. `edge` never wraps: the content key is created and wrapped by `worker`, and `edge` only
  unwraps it for the key endpoint and unwraps viewer secrets.
- `api` and `worker` wrap and unwrap: integrity signing seeds, webhook and viewer secrets (`api`
  seals, `worker` opens webhook secrets) and content keys. `DescribeKey` is how the provider
  resolves an alias to the key ARN before a wrap.
- Presigned URLs are signed with the role's credentials, so they stop working when the role's
  temporary credentials expire, even if the URL's own lifetime is longer.
- Run `cipherframe-server admin kms-rewrap` as a role that has `Encrypt`, `Decrypt` and `DescribeKey`
  (`api` or `worker`).

## Variables

Required: `region` and `assume_role_policies`. The rest have defaults; see `variables.tf`.
`example.tfvars` shows the shape with `dev-placeholder-` values.

`assume_role_policies` maps each of `api`, `edge` and `worker` to a trust policy JSON. For EKS with
IRSA the policy trusts your cluster's OIDC provider with `sts:AssumeRoleWithWebIdentity` and a
`sub` condition naming that role's service account (see `example.tfvars`). For an EC2 instance
profile, use one trust policy that lets `ec2.amazonaws.com` assume the role:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
```

then attach an instance profile for each role yourself (this module does not create one).
EKS Pod Identity works too, with a trust policy for `pods.eks.amazonaws.com`.

## Map the outputs to Cipherframe settings

| Output | Environment variable |
| --- | --- |
| `s3_region` | `CIPHERFRAME_S3_REGION` |
| `s3_source_bucket` | `CIPHERFRAME_S3_SOURCE_BUCKET` |
| `s3_delivery_bucket` | `CIPHERFRAME_S3_DELIVERY_BUCKET` |
| `kms_aws_key_id` | `CIPHERFRAME_KMS_AWS_KEY_ID` |
| `kms_aws_region` | `CIPHERFRAME_KMS_AWS_REGION` |

Also set `CIPHERFRAME_KMS_PROVIDER=awskms`. Leave the static credential variables
(`CIPHERFRAME_S3_ACCESS_KEY_ID`, `CIPHERFRAME_S3_SECRET_ACCESS_KEY`, `CIPHERFRAME_KMS_AWS_ACCESS_KEY_ID`,
`CIPHERFRAME_KMS_AWS_SECRET_ACCESS_KEY`) set to the empty string so the AWS SDK default chain picks up
the role (see docs/usage.md). Nothing here outputs a secret. Do not set `CIPHERFRAME_S3_ENDPOINT`
for AWS. When you use presigned delivery or browser uploads, set `cors_allowed_origins` to your
player and uploader origins.

## Use

```sh
cd deploy/terraform/aws
cp example.tfvars terraform.tfvars   # edit; terraform.tfvars is ignored by version control
terraform init
terraform plan
```

State and `.terraform.lock.hcl` are not committed. Use a remote backend for real use.

## Cost notes

S3 storage and request charges grow with your media (the delivery bucket holds every rendition of
every video). The KMS key costs a small monthly fee plus a per-request fee for each wrap and unwrap
(content keys are unwrapped when players request them). SSE-KMS
with `bucket_kms_key_arn` adds a second key and per-request charges, which the S3 bucket key setting
this module enables keeps low. IAM roles are free. There is no NAT, load balancer or compute here.
