# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M0-2)
- Deciders: project owner

## Context

Cipherframe is built under a decision protocol: the project owner makes every real choice, and each
choice must be traceable. Pending gates (P1 to P21) and any unlisted choice (a library, a schema shape,
a default value, a public API name) are decided explicitly before work that depends on them starts.

## Decision

- Every decision is recorded as an Architecture Decision Record in `docs/adr/`, numbered from 0001,
  using [`template.md`](template.md), on the day it is made.
- An ADR names the gate it closes (`Pn`, `Dn`, or `none`) and the options that were weighed.
- Accepted ADRs are not edited in substance. A changed decision gets a new ADR that supersedes the old
  one, and the old one's status is updated to point at it.
- [`README.md`](README.md) is the index and the decision log.

## Consequences

- Reviewers can trace any line of code back to a decision.
- Small decisions still cost an ADR. That is intended: asking early is cheaper than reworking later.
- ADRs record what was decided, not whether the implementation matches it. Tests do that.
