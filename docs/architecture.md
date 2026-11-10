# Architecture

> Status: skeleton (M0-4). Sections marked *pending* depend on open decision gates.

## Purpose

Cipherframe sits between private S3-compatible object storage and a browser. An embedding
application decides who may watch what. Cipherframe turns a source video into encrypted HLS, issues
short-lived revocable playback sessions, records access, signs what it produced, and deletes
verifiably.

## Roles

| Role | Responsibility |
|---|---|
| Control plane (`api`) | Assets, uploads, sessions, keys, deletion records, webhooks, quotas. Server-to-server only. |
| Data plane (`edge`) | Session-scoped playlists, the key endpoint, segment delivery (`proxy` or `presigned`). Browser-facing. |
| Worker | Probe, transcode, package, encrypt, hash, sign, purge, retention sweeps. Runs FFmpeg and FFprobe as separate processes. |
| CLI | Operator and integration tooling, including a public-key-only verifier. |
| Reference player | Demo browser player that attaches the session token to every request. |

Whether these are separate binaries or one binary with roles is **pending (P4)**.

## Storage

- A **source** bucket holds originals. Nothing served by Cipherframe references it (invariant I4).
- A **delivery** bucket holds encrypted segments, playlists and derived artifacts.
- Media bytes do not flow through the control plane in recommended configurations (I9).

## State

- Datastore and job queue: **pending (P2)**.
- Jobs use a language-neutral JSON envelope (`spec/jobs/`) so a non-Go worker can consume them
  (**pending P21** for the contract).

## Keys

Each asset has one active content key (I7), wrapped by a key-encryption key held in a key management
provider (AWS KMS, Vault Transit, GCP KMS; a development-only local provider is **pending P5**). See
[encryption.md](encryption.md).

## Lifecycle

`created → uploading → committed → processing → ready | failed → deleted`

Deletion enumerates storage, destroys the content key, re-lists to confirm nothing is left, and signs
a record. See [integrity.md](integrity.md).

## What this architecture does not protect against

See [threat-model.md](threat-model.md#out-of-scope). In short: screen capture, authorized viewers
keeping copies, scripted reassembly during a valid session, and compromise of the operator's own
storage or KMS credentials.
