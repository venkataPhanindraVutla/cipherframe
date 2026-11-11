# Privacy

> Status: the access trail and its privacy settings are implemented (M4-7), and the anomaly signals
> that read only the same data (M4-9). The final defaults and the
> remaining settings (retention, original file names, asset time-to-live) are pending gate P11.

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

Turning a setting off stops storing it for later rows; it does not erase rows already written.
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
  an email address or other direct identifier. Events are kept until retention is decided (P11, with the
  webhook outbox in M7); deleting a viewer's data must cover this table as well as the trail.
- Auto-revoke acts on a viewer's session on the strength of a counter. It is off by default, and the
  tenant, not Cipherframe, decides which kinds may do it.

## Settings (defaults pending P11)

Until gate P11 decides, the mechanism uses the most private values and nothing is deleted
automatically.

| Setting | Default now | Implemented |
|---|---|---|
| Asset time-to-live | pending | no |
| Store viewer IP address (`store_ip`) | off | yes, per tenant: `PUT /v1/privacy-settings` |
| Store viewer user agent (`store_user_agent`) | off | yes, per tenant |
| Store original filename | pending (none is accepted or stored today) | no |
| Access-log retention | pending: rows are kept until M6 | no (the monthly partitions and a tested drop function are in place, unused) |

## Deletion and retention

Deletion and retention expiry run the same verified purge flow; see [integrity.md](integrity.md).

## What this does not protect against

- Copies an authorized viewer made while watching.
- Data the embedding application stores about its own users.
- Backups or replicas of storage the operator runs outside Cipherframe's prefixes. Deletion
  destroys the content key, so encrypted copies there become unreadable, but plaintext copies made
  outside Cipherframe are not reachable.
