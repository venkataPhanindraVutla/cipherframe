# 0040. Retention and privacy defaults

- Status: Accepted
- Date: 2026-11-14
- Gate: P11
- Deciders: project owner

## Context

M6 (deletion and retention) needs the defaults that decide what Cipherframe keeps and for how
long. The access trail and its privacy settings already exist (M4-7) with the most private defaults
as placeholders, and the original file name, asset time-to-live and log retention were left to this
gate. Recordings are personal data (docs/privacy.md).

## Options considered

- **Asset time-to-live by default**: keep until deleted, 90 days, or one year.
- **Access trail and anomaly event retention**: 30 days, 90 days, or one year.
- **Viewer IP address and user agent**: off by default, IP on by default, or both on.
- **Original file name**: never stored, opt-in per tenant, or stored by default.

## Decision

- **Assets are kept until deleted.** There is no automatic deletion by default. M6-4 adds a
  per-asset time-to-live (set at creation or later) and an optional tenant-wide default; when one
  applies, the retention job runs the verified purge of M6-2 and leaves the signed deletion record
  of M6-3, covering both variants (ADR 0036).
- **The access trail (`playback_access_log`) and anomaly events (`playback_events`) are kept for 90
  days.** A deployment setting changes it (M6 names the variable and its bounds). Rows older than the
  window are removed by a scheduled job: whole monthly partitions once every row in them is past the
  window (the existing `playback_access_log_drop_partitions_before`), and row deletion for the rest
  and for `playback_events`, which is not partitioned.
- **Viewer IP address and user agent stay off by default** (today's behaviour). Tenants can still
  turn either on; turning it off later does not erase rows already written, and the 90-day window
  bounds how long such rows live.
- **The original file name is never stored.** Cipherframe's own code never reads one, but the tus
  library keeps a client's `Upload-Metadata` (which tus clients often fill with `filename`) in the
  upload's `.info` object in the source bucket. M6-5 drops all client upload metadata before it is
  stored, and adds a test that no file name reaches the database, storage, logs or manifests. The
  embedding application keeps its own title.

## Consequences

- Nothing disappears unless someone asked for it, so a tenant that needs minimisation must set a
  time-to-live; docs/privacy.md says this plainly.
- Investigations ("who watched this?") have a 90-day window, which also caps how long viewer IDs,
  and IP addresses where enabled, are kept.
- Deleting a viewer's data on request still covers the trail and the events tables (docs/privacy.md).
- Revisit if a tenant needs legal-hold or longer audit retention: that would be a per-tenant override,
  not a new default.
