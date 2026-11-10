# 0016. API-key pepper versioning

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-7; extends ADR 0009)
- Deciders: project owner

## Context

ADR 0009 stores API keys as `HMAC-SHA256(pepper, secret)`. A pepper may need rotating, for example
after a suspected leak, without breaking every integration at the same moment.

## Options considered

1. **Versioned pepper**: each hash records the pepper version that made it.
2. **A single pepper**: changing it invalidates all keys at once.

## Decision

Option 1.

- Peppers are configured as a versioned set (for example `CIPHERFRAME_API_KEY_PEPPERS_FILE` holding
  `version:secret` entries) plus the current version.
- Each stored key hash records its `pepper_version`. Verification uses that version's pepper.
- New and rotated keys always use the current version.
- An old pepper can be removed once no active key references it. The service reports how many keys
  still use each version, and refuses to start if a referenced version is missing.

## Consequences

- Pepper rotation becomes gradual: rotate keys at the clients' own pace, then retire the old pepper.
- One extra small column per key, and the pepper set becomes part of the secrets an operator backs up.
