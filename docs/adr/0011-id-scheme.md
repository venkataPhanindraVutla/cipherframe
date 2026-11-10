# 0011. ID scheme

- Status: Accepted
- Date: 2026-11-10
- Gate: none (M1-2)
- Deciders: project owner

## Context

Every row and every API object needs an identifier. IDs appear in logs, support requests, URLs and
signed records, so they should be ordered, compact and say what kind of object they name. Some IDs
also act as capabilities: anyone holding them gains access.

## Options considered

1. **Prefixed UUIDv7**: UUIDv7 in the database; a type prefix and base32 text in the API.
2. **Plain UUIDv7** everywhere.
3. **ULID strings** stored as text.

## Decision

Option 1.

- Database primary keys are `uuid` columns holding **UUIDv7** values (time-ordered, so inserts stay
  index-friendly).
- In the API and logs an ID is written as `<prefix>_<26 characters>`: the UUID's 128 bits in
  lowercase Crockford base32. Initial prefixes are `ten` (tenant), `cli` (client), `key` (API key)
  and `ast` (asset). New object types add a prefix in the ADR or task that introduces them.
- Parsing rejects an ID with the wrong prefix for the endpoint, so `cli_…` passed where `ast_…` is
  expected returns a not-found error and never reaches the database.
- **Session IDs are not UUIDs.** They are 256 bits from a CSPRNG, written `ses_<base32>`, because
  holding one grants playback.

## Consequences

- UUIDv7 encodes creation time to the millisecond; IDs therefore reveal roughly when an object was
  created. That is acceptable for these objects; anything where it would not be gets a random ID.
- A malformed ID is rejected before any query runs, so it cannot cause a database error.
- The text form is part of the public API and stable from v1.0.0.
