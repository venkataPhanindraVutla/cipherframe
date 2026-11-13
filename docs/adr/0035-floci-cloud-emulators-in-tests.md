# 0035. Floci cloud emulators in tests

- Status: Accepted
- Date: 2026-11-13
- Gate: none (amends the test strategy of ADR 0023)
- Deciders: project owner

## Context

ADR 0023 tests the GCP KMS provider only against an in-process fake that this project wrote, so
nothing independent of our own code checks it in normal CI. The storage layer is tested only against
SeaweedFS, so behaviour that SeaweedFS happens to share with our assumptions is never checked against
a second S3 implementation.

Floci (MIT) publishes local emulators for AWS (`floci/floci`) and GCP (`floci/floci-gcp`). Each is a
single container. A spike on 2026-11-12 ran our existing suites against them with no changes to the
tests:

- AWS KMS: the whole moto suite passed on Floci 2.4.0.
- GCP KMS: the provider conformance suite passed on floci-gcp 0.12.0 over gRPC, including
  associated-data binding with CRC32C checks, rotation and mixed key versions.
- S3: all storage tests passed on Floci 2.4.0 once `FLOCI_AUTH_VALIDATE_SIGNATURES=true` was set.
  Without it, Floci accepts a wrong secret and a presigned URL re-aimed at another host.

## Options considered

- Keep ADR 0023 unchanged.
- Add Floci where it adds an independent check: GCP KMS and a second S3 backend.
- Also replace moto with Floci for AWS KMS.

## Decision

- **GCP KMS**: an integration test runs the provider conformance suite against `floci/floci-gcp`.
  The in-process fake stays, because it injects faults an emulator cannot.
- **S3**: the storage integration tests run against SeaweedFS by default, and against `floci/floci`
  when `CIPHERFRAME_TEST_S3_BACKEND=floci`. CI runs both. Floci always runs with
  `FLOCI_AUTH_VALIDATE_SIGNATURES=true`, so the signature, wrong-credential and presigned-host tests
  keep their meaning.
- **AWS KMS** stays on moto. Floci passes the same suite, so there is nothing to gain from switching.
- Images are pinned by tag and digest, like every other test image.
- Floci is a test dependency only. SeaweedFS remains the object store of the development stack.

## Consequences

- Every cloud provider is checked in normal CI against something other than our own fake.
- Floci is young (the AWS emulator dates from February 2026, the GCP one from May 2026 and is still
  0.x). If an upgrade breaks a test that real clouds pass, pin the older digest or drop that check.
- Emulators can still differ from the real services. The opt-in real-cloud tests of ADR 0023 remain
  the release check.
