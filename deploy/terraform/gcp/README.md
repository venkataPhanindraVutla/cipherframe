# Cipherframe on Google Cloud (Terraform example)

An example, not a turnkey stack, and the project never applies it: CI only runs
`terraform fmt -check`, `init -backend=false` and `validate`, with no credentials (ADR 0054,
ADR 0056). Cipherframe talks to Cloud Storage through its S3-compatible XML API, so this path is
less proven than AWS (see "Limits" below). Read the plan before you apply it.

## What it creates

- Two buckets, `source` and `delivery`, with uniform bucket-level access and public access
  prevention enforced. Versioning is off by default (`bucket_versioning`). There is no expiry
  lifecycle, because purge deletes explicitly (ADR 0042); the only optional rule aborts unfinished
  multipart uploads in the source bucket (`abort_incomplete_multipart_days`). Objects are
  encrypted at rest with Google-managed keys.
- A Cloud KMS key ring and one symmetric `ENCRYPT_DECRYPT` key for the Cipherframe KEK, rotated
  every 90 days by default. The key has `prevent_destroy`; Cloud KMS keys cannot be fully deleted
  anyway, only their versions.
- One service account per server role (`<name_prefix>-api`, `-edge`, `-worker`), optional
  Workload Identity bindings (`workload_identity_members`), custom storage roles bound on the
  buckets, and KMS bindings on the key.
- Optionally (`create_hmac_keys = true`) one HMAC key per service account.

## Role to permission table

Derived from the code the same way as the AWS module (see its README for the call-by-call reasoning).
Cloud Storage permissions behind the S3 calls: `GetObject` and `HeadObject` need `objects.get`,
`ListObjectsV2` needs `objects.list`, deletes need `objects.delete`, uploads need `objects.create`
and the multipart calls need `multipartUploads.*`.

| Role | Source bucket | Delivery bucket | Cloud KMS key |
| --- | --- | --- | --- |
| `api` | `objects.create/get/list/delete`, `multipartUploads.create/abort/listParts` | `objects.create/get/list/delete` | `cryptoKeyEncrypterDecrypter`, `viewer` |
| `edge` | `objects.create/get/list/delete`, `multipartUploads.create/abort/listParts` | `objects.get/list` | `cryptoKeyDecrypter`, `viewer` |
| `worker` | `objects.get/list/delete`, `multipartUploads.abort/list` | `objects.create/get/list/delete` | `cryptoKeyEncrypterDecrypter`, `viewer` |

- Each row is a custom role (`<prefix>_<role>_<bucket>`) bound on one bucket, never on the project.
- `viewer` gives `cloudkms.cryptoKeys.get`, which the provider calls before wrapping and unwrapping.
- `edge` only unwraps: content keys and viewer secrets. `worker` creates content keys.
- No object-name condition is set. Every role's readiness check reads `_cipherframe/readiness-probe`,
  outside the `t/` tree that holds all real objects, and listing calls cannot be conditioned on the
  object name unless the caller passes the prefix, so a condition would narrow little and could make
  roles unready. The AWS module narrows by prefix with IAM resource ARNs; this module cannot do the
  same, and the table is the honest limit.

## Map the outputs to Cipherframe settings

| Output | Environment variable |
| --- | --- |
| `s3_endpoint` | `CIPHERFRAME_S3_ENDPOINT` |
| `s3_source_bucket` | `CIPHERFRAME_S3_SOURCE_BUCKET` |
| `s3_delivery_bucket` | `CIPHERFRAME_S3_DELIVERY_BUCKET` |
| `kms_gcp_key_name` | `CIPHERFRAME_KMS_GCP_KEY_NAME` |
| `hmac_access_ids[role]` | `CIPHERFRAME_S3_ACCESS_KEY_ID` (that role) |
| `hmac_secrets[role]` | `CIPHERFRAME_S3_SECRET_ACCESS_KEY` (that role, sensitive) |

Also set `CIPHERFRAME_KMS_PROVIDER=gcpkms`, `CIPHERFRAME_S3_REGION` to a region value the XML API
accepts (`auto` is the documented placeholder) and leave `CIPHERFRAME_KMS_GCP_CREDENTIALS_FILE`
unset so Application Default Credentials (Workload Identity or an attached service account) are used.

## HMAC keys

The S3 API signs requests with an HMAC key, which belongs to one service account. The default is a
manual step, so no secret passes through Terraform state:

```sh
gcloud storage hmac create SERVICE_ACCOUNT_EMAIL   # prints the access id and the secret once
```

Store the pair in your secret manager and give it to that role as `CIPHERFRAME_S3_ACCESS_KEY_ID`
and `CIPHERFRAME_S3_SECRET_ACCESS_KEY`. With `create_hmac_keys = true` Terraform creates them
instead. The secret is then in state, so use an encrypted remote backend, and the `hmac_secrets`
output is marked sensitive: it is hidden in plan and apply output and shown only by
`terraform output -json hmac_secrets`.

## Use

```sh
cd deploy/terraform/gcp
cp example.tfvars terraform.tfvars   # edit; terraform.tfvars is ignored by version control
terraform init
terraform plan
```

State and `.terraform.lock.hcl` are not committed.

## Limits

- This example has only been validated (`terraform validate`), never applied, and Cipherframe's
  S3 client has not been tested against Cloud Storage's XML API by the project. Treat the first
  upload, multipart and tus run as a test of your own.
- The multipart permission names follow the Cloud Storage IAM reference; confirm them against the
  current reference when you apply.
- Presigned URLs from the XML API need HMAC keys, which is why they are in the module.

## Cost notes

Cloud Storage charges for stored bytes, operations and egress; the delivery bucket holds every
rendition of every video. Cloud KMS charges per key version and per operation (content keys are
unwrapped when players request them). Service accounts and custom roles are free. There is no
network or compute here.
