# 0054. Operations and release tooling

- Status: Accepted
- Date: 2026-11-22
- Gate: none (M9-2, M9-3, M9-4, M9-6; choices the plan left open)
- Deciders: project owner

## Context

M9 ships a Helm chart, a Terraform example, load tests with published numbers and release
automation. The plan names the outcomes but not the tools, which clouds the example covers, or
how the chart gets its database. Cipherframe needs Postgres and S3-compatible storage; it uses
no Redis.

## Options considered

- **Terraform example:** AWS only; AWS and GCP; provider-neutral placeholders.
- **Helm and Postgres:** external Postgres only; an optional CloudNativePG cluster; the Bitnami
  `postgresql` subchart.
- **Release:** GoReleaser with cosign keyless signing; cosign with a stored key; plain GitHub
  Actions steps.
- **Load tests:** a small Go tool in the repository; k6 scripts.

## Decision

- **Terraform (M9-3): AWS and GCP.** Two example modules under `deploy/terraform/`:
  - AWS: an S3 bucket, one IAM role and least-privilege policy per server role, and an AWS KMS key.
  - GCP: a GCS bucket used through its S3-compatible interface, one service account per server
    role, and a Cloud KMS key.
- **Helm (M9-2): external Postgres only.** The chart reads the database connection string from a
  Secret and runs migrations as a Job. No database is bundled; the docs point to managed Postgres
  or the CloudNativePG operator.
- **Release (M9-6): GoReleaser and cosign keyless.**
  - GoReleaser builds the CLI binaries and the container images and pushes the images to ghcr.io.
  - Images are signed with cosign keyless through GitHub's OIDC token; no signing key is stored.
  - Each release carries SPDX SBOMs and SLSA provenance, and its changelog comes from pull
    request titles.
- **Load tests (M9-4): a small Go tool.** A program in the repository uses the generated API client
  to create sessions and play them as a viewer would, fetching playlists, keys and segments and
  sending heartbeats, in both `proxy` and `presigned` delivery. It also measures transcode
  throughput. Raw results are published as CSV beside a methodology document.

## Consequences

- CI checks both Terraform modules with `terraform fmt`, `validate` and a plan against mocked
  credentials. Neither is applied from CI, and the GCP module is never applied by the project.
- Operators bring their own Postgres; a cluster without one needs the operator or a managed
  service first.
- Verifying an image needs the cosign CLI and checks the signer identity (this repository's release
  workflow) rather than a public key file.
- The load tool shares the client with the CLI, so it follows API changes without a second
  implementation. Its numbers depend on the machine they were measured on, which the methodology
  document records.
