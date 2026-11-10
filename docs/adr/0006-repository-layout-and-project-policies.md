# 0006. Repository layout and project policies

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M0-1 choices raised under the decision protocol)
- Deciders: project owner

## Context

Scaffolding the repository (M0-1) involved choices the decision register does not list: how the Go
code is organised, where vulnerability reports go, which code of conduct applies, which dependency
licences are acceptable, and how commits are authored.

## Options considered

Layout:

1. **One root module**: the root `go.mod` is the service; the v2 Go SDK becomes its own module later.
2. **Multi-module from day one** (`go.work`): cleaner v2 split, more version wiring before anything
   exists.
3. **Public `pkg/` tree**: commits to a public Go API before v2.0.0 is designed.

Disclosure channel: GitHub private vulnerability reporting, an email address, or both.

## Decision

| Concern | Decision |
|---|---|
| Layout | One root module. `cmd/<binary>/` for binaries (named after P4), `internal/<area>/` for service code, `spec/` for the OpenAPI spec and job schemas, `docs/`, `deploy/`, `web/player/`. The v2 Go SDK becomes a separate module under `sdks/go/`, with `go.work` added then. |
| Vulnerability disclosure | GitHub private vulnerability reporting (enabled on the repository) as the primary channel; `phanivutla2004@gmail.com` as the fallback. |
| Code of conduct | Contributor Covenant 2.1; enforcement contact `phanivutla2004@gmail.com`. |
| Dependency licences | Allowlist: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0. Anything else needs an ADR. Enforced in CI with `go-licenses`. |
| Commits | Authored as `Venkat <phanivutla2004@gmail.com>`, with no AI co-author trailers. |
| Merging | One branch per task ID, merged by merge commit once CI is green; the branch is deleted after merging. |

## Consequences

- Nothing in `internal/` is importable by other modules. Public Go APIs arrive deliberately with the
  v2.0.0 SDK.
- The allowlist excludes GPL, LGPL and AGPL code. FFmpeg is unaffected because it is never linked;
  the licence of any FFmpeg build shipped in an image is decided at P8.
- The disclosure email is public in `SECURITY.md` and `CODE_OF_CONDUCT.md`.
