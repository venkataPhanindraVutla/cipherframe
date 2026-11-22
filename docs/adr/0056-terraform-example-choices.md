# 0056. Terraform example choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-3; choices ADR 0054 leaves open)
- Deciders: implementation, pending the project owner's review

## Context

ADR 0054 fixes the scope of the Terraform example (AWS and GCP modules under `deploy/terraform/`,
one identity per server role, a KMS key). It leaves open how the roles authenticate, how buckets
are encrypted, how the GCP S3 credentials are handled, and how far CI checks the modules.

## Options considered

- **Role authentication on AWS:** hard-code IRSA; hard-code an EC2 instance profile; take the trust
  policy as an input.
- **Bucket encryption on AWS:** SSE-S3; SSE-KMS under the Cipherframe KEK; SSE-KMS under a separate,
  optional key.
- **GCP storage permissions:** predefined roles (`objectUser`, `objectViewer`); custom roles per
  role and bucket; IAM conditions on the object name.
- **GCP HMAC keys:** always created by Terraform; never created; opt-in.
- **CI:** `fmt` and `validate` only; plus `tflint`; plus a plan against mocked credentials.

## Decision

- **Trust policy is an input** (`assume_role_policies`, one JSON per role). IRSA, Pod Identity and
  instance profiles all differ only in this policy, and each role needs its own subject.
- **SSE-S3 by default; SSE-KMS only with an optional separate key** (`bucket_kms_key_arn`). Using
  the KEK for S3 would give every role `GenerateDataKey` on the key that wraps content keys. The
  KEK stays usable only for wrap and unwrap, and `edge` gets `Decrypt` only.
- **Versioning off, no expiry lifecycle.** Purge deletes explicitly (ADR 0042), and old versions
  would survive it. The only optional lifecycle rule aborts unfinished multipart uploads.
- **Least privilege from the code.** The AWS policies are scoped to the key prefixes in
  `internal/storage/keys`, plus the readiness probe key and `ListBucket` that every role needs.
  The README table records the derivation.
- **GCP: custom roles per (role, bucket), no object-name conditions.** The readiness probe key sits
  outside the `t/` tree, and list calls cannot be conditioned on the name without the prefix, so a
  condition narrows little and risks unready roles. The AWS module is therefore tighter than the
  GCP one, and the GCP README says so.
- **GCP HMAC keys are a documented manual step by default**, with an opt-in `create_hmac_keys`
  whose secret output is `sensitive` and is also stored in state.
- **CI runs `terraform fmt -check`, `init -backend=false` and `validate`** for both modules, with a
  pinned Terraform and a SHA-pinned action. No credentials. It does **not** run a plan against mocked
  credentials, which ADR 0054 mentioned: a plan needs provider API calls, so mocks would test the
  mocks. It does not run `tflint` either; adding a pinned linter is left for a later change.
- **Provider and version pins:** `required_version >= 1.6.0`, `aws ~> 6.0`, `google ~> 8.0`.
  Lock files and state are git-ignored; `example.tfvars` is the only committed variables file.

## Consequences

- An operator writes three trust policies as input, but it works with any workload identity
  system and the module never needs to know the cluster.
- The GCP path is validated, not applied, and Cipherframe's S3 client is untested against Cloud
  Storage's XML API by the project. The README states this. Applying it for the first time is the
  operator's test.
- Revisit when a Helm chart (M9-2) defines service account names, when a plan check becomes
  worthwhile, or when GCS supports prefix-conditioned list permissions without the listing prefix.
