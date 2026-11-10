# API

> Status: skeleton (M0-4). The API is defined in M1-6.

## Source of truth

`spec/openapi.yaml` (OpenAPI 3.1) is the source of truth. Server interfaces are generated from it
(ADR 0004), and a contract test fails CI if the running API and the spec diverge.

## Surfaces

| Surface | Callers | Authentication |
|---|---|---|
| Control plane | Embedding application servers | API keys (M1-7); JWT and signed callback (M4-8, pending P7) |
| Data plane | Browsers | Short-lived playback tokens (pending P6) |
| Well-known keys | Anyone | None (public keys only) |

## Conventions (pending M1-2)

The error model (stable codes, request ids, retryable flag) and the ID scheme are proposed in an ADR
during M1.

## What this does not protect against

- A leaked API key grants its client's full control-plane access until it is rotated.
- The control plane does not decide who may watch what; the embedding application does.
