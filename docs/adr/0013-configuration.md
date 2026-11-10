# 0013. Configuration

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-1)
- Deciders: project owner

## Context

Cipherframe runs under Docker Compose, Kubernetes and plain processes. Secrets must come only from the
environment or from files and must never be logged (M1-1, pitfall 9). A misconfiguration should stop
the process at startup, not halfway through a job.

## Options considered

1. **Environment variables with `*_FILE` variants**, strict in production.
2. **A YAML file with environment overrides**.

## Decision

Option 1.

- All settings are `CIPHERFRAME_*` environment variables, parsed into one typed, validated struct at
  startup. Invalid values stop the process with an error that names the variable, never its value.
- Every secret can instead be read from a file: `CIPHERFRAME_X_FILE=/run/secrets/x`. Setting both is
  an error.
- `CIPHERFRAME_ENV` is `development` (default) or `production`. In `production` the process refuses
  to start if any required secret is missing or still equals a development placeholder.
- Storage and cloud credentials have three states: **unset** (development default), **empty string**
  (use the provider's own credential chain, such as an instance role), or **a value**. The states are
  never collapsed, so a development credential can never be silently sent to a real provider.
- Secret values are a distinct type whose string and JSON forms print `[redacted]`. A test loads a
  full configuration, prints and logs it, and asserts that no secret value appears.

## Consequences

- No config file format to maintain, and nothing in the repository can hold a real secret by accident.
- Large deployments set many variables; Helm values and the Compose file document them.
- Defaults are chosen to be safe, and each is listed in `docs/usage.md` as tasks add them.
