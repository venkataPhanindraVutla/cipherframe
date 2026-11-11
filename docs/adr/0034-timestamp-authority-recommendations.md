# 0034. Timestamp authority recommendations

- Status: Accepted
- Date: 2026-11-12
- Gate: P10
- Deciders: project owner

## Context

D7 makes RFC 3161 anchoring optional and off by default (M5-5). The documentation should still
help an operator who wants it pick an authority.

## Options considered

- Commercial and community authorities; commercial only; no names, only a configuration guide.

## Decision

- The documentation names the free public RFC 3161 endpoints of DigiCert, Sectigo and GlobalSign,
  which are WebTrust-audited certificate authorities, and FreeTSA as a community option.
- No authority is enabled by default. The documentation says the operator chooses an authority and
  accepts its terms, and that the request carries only a digest, never content.
- The endpoint URLs are checked when the documentation is written and dated there, because
  providers change them.

## Consequences

- Naming an authority is not an endorsement. The verifier validates tokens offline against the
  authority's certificate chain, which the operator supplies or the documentation points to.
