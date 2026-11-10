# 0009. Tenancy and API keys

- Status: Accepted
- Date: 2026-11-10
- Gate: P7 (API-key part; JWT and signed callback are decided before M4)
- Deciders: project owner

## Context

M1-7 needs clients, tenants and API-key authentication. Rotating a key must preserve ownership of
assets, sessions and audit rows (pitfall 7). Quotas are per client, while branding and ML opt-ins
are per tenant.

## Options considered

1. Tenant > client > one key per client, rotated in place.
2. A single level where tenant and client are the same thing.
3. Tenant > client > several named, scoped keys per client.

Scope sets considered: five coarse scopes, two roles, one scope per action.

## Decision

Option 3, with five coarse scopes.

**Model**

- **Tenant**: the isolation boundary. Owns assets. Holds branding, quotas and ML opt-ins.
- **Client**: one embedding application or environment inside a tenant. Sessions and audit rows
  record the client that acted.
- **API key**: a named credential belonging to a client, with a set of scopes. A client may hold
  several keys.

**Scopes**

| Scope | Allows |
|---|---|
| `assets:read` | Read assets, status, deletion records |
| `assets:write` | Create, upload, process and delete assets |
| `sessions:write` | Create and revoke playback sessions |
| `webhooks:manage` | Configure webhooks and replay deliveries |
| `admin` | Manage keys and quotas for the tenant |

New keys get every scope except `admin` unless scopes are given explicitly.

**Format and storage**

- Format: `cf_<prefix>_<secret>`. The prefix identifies the key (lookup and display); the secret
  is 32 random bytes, base64url-encoded.
- At rest: the prefix and `HMAC-SHA256(pepper, secret)`. The pepper comes from an environment
  variable or file and is never logged. Comparison is constant-time.
- The full key is shown once at creation or rotation and never again.

**Rotation**

- Rotation replaces the secret on the **same key row**. Ownership never moves.
- The previous secret stays valid for an overlap window, 10 minutes by default (0 allowed), so
  deployments can roll over.
- Revoking a key disables it immediately; its audit rows remain.

**Bootstrap**: the first tenant, client and admin key are created with the CLI.

## Consequences

- Least privilege is available without a full per-action permission model.
- Scope names are public API; adding scopes is compatible, renaming or splitting them is not.
- HMAC with a pepper is appropriate because secrets are high-entropy random values. A leaked
  database without the pepper does not reveal usable keys. A leaked pepper and database together
  still don't give the original secrets, but they do let someone test candidate keys.
- This ADR does not cover JWT or signed-callback authorization for playback (P7, before M4).
