# Privacy

> Status: skeleton (M0-4). Defaults are pending gate P11.

## Principles

- Recordings, transcripts, subtitles and thumbnails are treated as personal data.
- Cipherframe records an **access trail** (who, when, which session events) and nothing more. There
  are no viewer behavioural analytics (invariant I10).
- A playback session stores the embedding application's `viewer_id` and nothing else about the
  viewer. It must be a pseudonymous identifier, never an email address or other direct identifier
  ([api.md](api.md#playback-sessions-and-settings-adr-0028-0030)).
- ML features (v2.1) are opt-in per tenant, run locally, and send no media, audio, frames or
  transcripts to third parties.
- Every derived artifact is registered with the purge job and counted in the signed deletion record
  (I6).

## Settings (pending P11)

| Setting | Default |
|---|---|
| Asset time-to-live | pending |
| Store viewer IP address | pending |
| Store viewer user agent | pending |
| Store original filename | pending |
| Access-log retention | pending |

## Deletion and retention

Deletion and retention expiry run the same verified purge flow; see [integrity.md](integrity.md).

## What this does not protect against

- Copies an authorized viewer made while watching.
- Data the embedding application stores about its own users.
- Backups or replicas of storage the operator runs outside Cipherframe's prefixes. Deletion
  destroys the content key, so encrypted copies there become unreadable, but plaintext copies made
  outside Cipherframe are not reachable.
