# Privacy

> Status: the access trail and its privacy settings are implemented (M4-7), and the anomaly signals
> that read only the same data (M4-9). The defaults (gate P11, [ADR 0040](adr/0040-retention-and-privacy-defaults.md))
> and the retention mechanisms (M6) are implemented: verified asset deletion, a per-asset and per-tenant
> time-to-live, the access-trail retention window, and no original file name is ever stored.

## Principles

- Recordings, transcripts, subtitles and thumbnails are treated as personal data.
- Cipherframe records an **access trail** (who, when, which session events) and nothing more. There
  are no viewer behavioural analytics (invariant I10): nothing records which segment, rendition or
  position a viewer fetched, and nothing records what the player did. Segment requests are only
  counted per session. See [What the access trail records](#what-the-access-trail-records).
- A playback session stores the embedding application's `viewer_id` and nothing else about the
  viewer. It must be a pseudonymous identifier, never an email address or other direct identifier
  ([api.md](api.md#playback-sessions-and-settings-adr-0028-0030)).
- ML features (v2.1) are opt-in per tenant, run locally, and send no media, audio, frames or
  transcripts to third parties.
- Every derived artifact is registered with the purge job and counted in the signed deletion record
  (I6).
- **Nothing disappears unless someone asked for it.** Assets are kept until deleted, so a tenant that
  needs data minimisation must set a time-to-live (see [Retention](#retention-and-deletion)).

## What the access trail records

One row per session event in `playback_access_log` ([api.md](api.md#the-access-trail-and-the-privacy-settings)
lists the events and how to read them): a session created, refused, revoked, ended or expired, the
master playlist fetched, the key fetched or refused, an accepted heartbeat (at most one per session per
5 minutes), and a `segments` row with how many segment requests a session made in the last 30 seconds.

| Column | What it holds |
|---|---|
| tenant, asset | Which tenant and asset the event concerns. |
| session hash | The SHA-256 of the session ID. Never the ID or a token. Empty for a refused creation. |
| viewer ID, auth method | The pseudonymous ID your application chose, and how the session was authorised. Empty when a refused authorization names no viewer. |
| event, time | What happened and when (UTC). |
| segments served | A count, on `segments` rows only. |
| request ID | The `X-Request-Id` of the request, to correlate with your own logs. |
| IP address | **Only if the tenant turned `store_ip` on.** The connecting peer address. |
| user agent | **Only if the tenant turned `store_user_agent` on.** Cut to 256 characters. |

The IP address and user agent are the only data about the viewer's device, and **both are off by
default**. They are never stored for events your server caused (API-key session creation, revocation) or
nobody did (expiry). Cipherframe does not read `X-Forwarded-For`, because a client can set it to
anything: behind a reverse proxy the stored address is the proxy's.

Turning a setting off stops storing it for later rows; it does not erase rows already written (the
retention window below does, after `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`, 90 days by default).
The trail is best effort and can lose events under overload, so it is not a complete or tamper-evident
record (see [api.md](api.md#the-access-trail-and-the-privacy-settings)). Reading it needs the
`assets:read` scope of the tenant; the settings need `admin`.

## The anomaly signals use only the access-trail data

Cipherframe raises anomaly signals ([api.md](api.md#anomaly-signals-m4-9)): a token or session asking
for the key too often, a viewer refused for the session limit, many sessions created for one viewer,
segments served to a session that never fetched the key. They are not viewer analytics, and they do not
change invariant I10:

- Every signal is a comparison of a **count or a time** against a threshold the tenant set: how many
  key requests a token or session made, how many sessions a viewer created in 10 minutes, how many
  segment requests a session made against whether it ever got the key. The inputs are the counters
  playback already keeps to enforce its limits and the same segment count the access trail keeps. No
  new data about the viewer is collected for them.
- Nothing is learned about **what** was watched: not which segment, rendition, position or title, and
  nothing the player did. There is no profile, no history across sessions beyond the viewer ID the tenant
  chose, and no scoring.
- An event (`playback_events`) holds the tenant, the asset, the viewer ID your application chose, the
  SHA-256 of the session ID, the time and a few integers (the threshold and the observed count). It
  holds no token, no session ID, no IP address and no user agent. The events API shows a session only as
  the same 8-character fingerprint the access trail uses.
- The viewer ID in an event is the same pseudonymous ID as in the trail, so the same advice applies: never
  an email address or other direct identifier. Events are kept for the same retention window as the
  trail (90 days by default); deleting a viewer's data on request must cover this table as well as the
  trail.
- Auto-revoke acts on a viewer's session on the strength of a counter. It is off by default, and the
  tenant, not Cipherframe, decides which kinds may do it.

## Settings and defaults (ADR 0040)

| Setting | Default | Where |
|---|---|---|
| Asset time-to-live | none: assets are kept until deleted | per asset (`expires_at` or `ttl_seconds` on create and `PATCH /v1/assets/{asset_id}`), or the tenant default `asset_ttl_seconds` in `PUT /v1/privacy-settings` |
| Store viewer IP address (`store_ip`) | off | per tenant: `PUT /v1/privacy-settings` |
| Store viewer user agent (`store_user_agent`) | off | per tenant |
| Original file name | never stored, and there is no setting to store it | none |
| Access-trail and anomaly-event retention | 90 days | the deployment: `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`, 1 to 3650 |

**IP address and user agent** stay off unless a tenant turns them on. Turning one on affects the rows
written afterwards, turning it off does not erase rows already written, and the retention window bounds
how long such rows live.

**The original file name is never stored.** Cipherframe's own code never reads one: the API has no file
name member (a `filename` or `title` in a create request is ignored), a multipart part's file name
headers are ignored, and a tus client's `Upload-Metadata`, which tus clients usually fill with the file
name, is dropped before tusd writes the upload's `.info` object in the source bucket. The only metadata
an upload keeps is the content type your application declared when it created the asset. A test
uploads with `filename` metadata and scans the database, both buckets (keys and contents), the logs
and every response for it. Keep the title in your own application, next to the asset ID.

## Retention and deletion

- **Assets are kept until deleted.** Cipherframe never deletes an asset on its own unless a
  time-to-live applies. **Set a time-to-live if you need minimisation**: give each asset a `ttl_seconds`
  (or `expires_at`) when you create it, or set the tenant default `asset_ttl_seconds` so every new asset
  gets one. Existing assets keep the expiry they were created with; `PATCH /v1/assets/{asset_id}`
  changes or clears it.
- **Deletion** (`DELETE /v1/assets/{asset_id}`) and **retention expiry** (the worker's retention job,
  every five minutes) run the same verified purge: every object of the asset in both buckets, both
  variants included, is deleted, the content keys are destroyed (crypto-shredding), storage is listed
  again to confirm it is empty, and a signed deletion record is left. See
  [integrity.md](integrity.md#verifiable-deletion). The record names counts, sizes and key IDs, never
  content, a file name or anything about a viewer, and it stays fetchable after the asset is gone.
- **The access trail and the anomaly events are kept for 90 days by default**
  (`CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`). A scheduled job drops whole monthly partitions past the
  window and deletes older rows of the rest and of `playback_events`. That caps how long viewer IDs,
  and IP addresses and user agents where enabled, are kept. Rows are removed on that schedule, not
  per asset: deleting an asset does not erase its trail early.
- Not covered by a window yet: the audit log (`audit_events`, who did what with an API key) and the
  playback session rows (which hold the viewer ID and no address). Both are kept until a later
  change decides (see [roadmap.md](roadmap.md)).

## What this does not protect against

- Copies an authorized viewer made while watching.
- Data the embedding application stores about its own users.
- Backups or replicas of storage the operator runs outside Cipherframe's prefixes. Deletion
  destroys the content key, so encrypted copies there become unreadable, but plaintext copies made
  outside Cipherframe are not reachable.
