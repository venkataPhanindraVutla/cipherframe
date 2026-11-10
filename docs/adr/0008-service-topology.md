# 0008. Service topology

- Status: Accepted
- Date: 2026-11-10
- Gate: P4
- Deciders: project owner

## Context

Cipherframe has three server roles: `api` (server-to-server control plane), `edge` (browser-facing
data plane: playlists, key endpoint, segments) and `worker` (FFmpeg and other background jobs). They
scale and fail differently, and FFmpeg should not run next to the browser-facing endpoint.

## Options considered

1. **One binary with selectable roles**: one build, roles deployed separately.
2. **Three binaries**: smallest code per process; three images and more release wiring.
3. **One process running everything**: simplest; no independent scaling or failure isolation.

## Decision

- One server binary, `cmd/cipherframe-server`, started with `--role=api`, `--role=edge`,
  `--role=worker`, or a comma-separated list (for example `--role=api,edge,worker` in Compose).
- The CLI is a separate binary, `cmd/cipherframe` (M8).
- `internal/api`, `internal/edge` and `internal/worker` may import shared packages under
  `internal/` but never each other. A `depguard` lint rule enforces this.
- Two images: `cipherframe-server` (api and edge, no FFmpeg) and `cipherframe-worker` (worker, with
  FFmpeg and FFprobe).
- Helm deploys each role as its own Deployment; the worker autoscales on queue depth.

## Consequences

- One build and one version for all roles; mixed-version roles are not supported in a deployment.
- The api/edge image contains no FFmpeg, keeping the browser-facing attack surface small.
- Code for all roles exists in the binary, so role separation relies on configuration and the import
  rule, not on the binary contents.
