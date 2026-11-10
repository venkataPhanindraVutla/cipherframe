# 0003. Repository owner and Go module path

- Status: Accepted
- Date: 2026-11-10
- Gate: P1
- Deciders: project owner

## Context

The Go module path is permanent once anything imports it: moving the repository later changes the
path and breaks every import. The name's availability was checked on 2026-11-10:

| Namespace | Finding |
|---|---|
| GitHub `CipherFrame` | Taken (an unrelated personal account, created 2022). |
| GitHub `cipherframe-dev`, `cipherframehq` | Free. |
| npm `cipherframe`, `@cipherframe/sdk` | Unclaimed (the npm org page could not be checked automatically). |
| PyPI `cipherframe` | Unclaimed. |
| `cipherframe.com` | Registered by someone else. |
| `cipherframe.dev` | Not registered at the time of the check. |
| GitHub repositories named CipherFrame | About 20, all small unrelated projects with no stars. |

## Options considered

1. **New org `cipherframe-dev`**: neutral home, needs an org to be created.
2. **Vanity path `cipherframe.dev`**: survives a host or org move; needs a domain and a redirect page.
3. **New org `cipherframehq`**: as option 1 under a different name.
4. **Owner's personal account**: no setup; a later move to an org changes the module path.

## Decision

The repository lives under the owner's personal GitHub account. The Go module path is:

```
github.com/venkataPhanindraVutla/cipherframe
```

## Consequences

- No org or domain is needed to start.
- Moving to an org later is a breaking change for every Go importer (a major version and a new path).
  If that is likely, it is cheapest to do before v2.0.0 publishes the Go SDK.
- This ADR does not reserve any npm, PyPI or domain name. Package names and scopes are decided at P19,
  and nothing is published before then.
