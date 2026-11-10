# 0002. Confirmed baseline decisions (D1 to D10)

- Status: Accepted
- Date: 2026-11-10
- Gate: D1 to D10
- Deciders: project owner (confirmed in the build plan)

## Context

The build plan fixes ten decisions before any code is written. This ADR seeds the decision log with
them so later ADRs can reference them by ID.

## Decision

| ID | Decision |
|---|---|
| D1 | Name **Cipherframe**. License **Apache-2.0**. |
| D2 | Backend core (API, edge, worker, CLI) in **Go**. Player and JS SDK in **TypeScript**. **Python** for the Python SDK and the v2.1 ML worker. |
| D3 | Key management providers in v1: **AWS KMS**, **HashiCorp Vault (Transit)**, **GCP KMS**. |
| D4 | Datastore and job queue: proposed by the implementer, confirmed by the owner (gate P2). |
| D5 | v1 includes four extras, built last and allowed to slip to v1.1: HEVC/AV1 renditions, content-key re-key, hardware-accelerated encoding, CDN signed URLs (CloudFront/Cloudflare). |
| D6 | Resumable upload: **both** S3 multipart (presigned parts) **and** tus. |
| D7 | Anchoring: **RFC 3161 timestamping only**; the Time-Stamping Authority is configurable; **off by default**. No hash-chain feature. |
| D8 | v2.1 ML worker: **CPU-only by default**, optional GPU image. |
| D9 | Deployment artifacts in v1: **Docker Compose**, **Helm chart**, **Terraform example**. |
| D10 | Versioning: v1.0.0 = service; v2.0.0 = npm, Go and Python packages/SDKs; v2.1.0 = ML features (minor). |

## Consequences

- Changing any of these requires a new superseding ADR and the owner's explicit answer.
- D4 is a placeholder: the actual datastore and queue are decided at P2 before M1.
