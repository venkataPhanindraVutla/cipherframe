# 0043. Subtitle and watermark parameters

- Status: Accepted
- Date: 2026-11-15
- Gate: P12
- Deciders: project owner

## Context

M7 adds subtitles (M7-1), a per-viewer overlay watermark (M7-3) and a per-tenant brand logo (M7-4).
Invariant I2 allows one canonical rendition set per asset, and I3 says per-viewer identity is shown
only as a client-side overlay. A brand logo may be burned in because it is the same for every
viewer. The overlay is deterrence only: anyone who controls the player can remove it.

## Options considered

- **Overlay text**: viewer ID, session code and time; session code and time only; those plus a
  free-text tenant label.
- **Overlay movement**: jump between grid positions every 30 seconds; the same every 10 seconds; a
  slow continuous drift.
- **Brand logo**: PNG in a corner with opacity; PNG or SVG in a corner; PNG at any position.
- **Subtitles**: WebVTT and SRT; WebVTT only; also styled formats (TTML, SCC).

## Decision

**Overlay watermark (M7-3)**

- The template may use only `{session_code}`, `{date}` and `{time}`. The viewer ID, names, emails
  and any other tenant-supplied text are not available to it. Literal template text is the tenant's
  own, sanitized and length-capped like every inserted value.
- `{session_code}` is a short code derived from the session ID. It is not the session ID or the
  token, and it cannot be used to act on the session. A tenant maps a leaked code back to a viewer
  through the access trail.
- `{date}` and `{time}` are the viewer's current time in UTC, so a recording also shows when it was
  made.
- The overlay drifts slowly and continuously across the frame along a path seeded from the session
  ID: the same session always gives the same path, and different sessions give different ones.

**Brand logo (M7-4)**

- PNG only, at most 256 KB and 1024 pixels on its longer side.
- Placed in one of the four corners, scaled to a fixed share of the video width and blended at an
  opacity from 10 to 100 percent.
- Burned in at transcode, recorded per asset and in the signed manifest. A new or changed logo
  applies to assets transcoded afterwards; existing assets keep theirs unless they are re-transcoded.

**Subtitles (M7-1)**

- WebVTT, or SRT converted to WebVTT on upload.
- Up to 20 tracks per asset, each at most 2 MB, with a BCP 47 language tag, a label and a default flag.
- The transcript import endpoint (timed text to a subtitle track) from the build plan is included.
- Tracks are hashed into the manifest, served only through a playback session and registered with
  the purge (I6).

## Consequences

- The overlay carries no personal data. Tracing a leak needs the tenant's access trail, which is
  kept for the retention window (ADR 0040), so a leak found after that window cannot be traced.
- A continuous drift is the hardest overlay to crop and the most noticeable to viewers. The player
  should keep it subtle (low opacity, small text).
- Styled subtitle formats are out of scope. Tenants convert them to WebVTT before upload.
- SVG logos are out of scope, which keeps an SVG parser off the server.
