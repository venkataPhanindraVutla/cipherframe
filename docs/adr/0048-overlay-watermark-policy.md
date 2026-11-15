# 0048. Overlay watermark policy: settings, session code, drift path

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (M7-3, details under P12)
- Deciders: implementer; the owner reviews the choices below. The parameters themselves were decided
  in [ADR 0043](0043-subtitle-and-watermark-parameters.md).

## Context

ADR 0043 fixed what the overlay shows (`{session_code}`, `{date}`, `{time}` only), that the player draws
it, that it drifts continuously along a path seeded from the session ID, and that a leaked code is
mapped back through the access trail. M7-3 had to decide the rest: where the settings live, how the
code relates to the trail's fingerprint, what the session response carries, and the exact path so that
any player reproduces it.

## Decisions

**The overlay is deterrence only.** It is drawn client-side, never burned in (I2, I3), and anyone who
controls the player can remove it. The API reference, the privacy page and the OpenAPI text say so.

**Settings are their own resource.** `GET`/`PUT /v1/overlay-settings` (scope `admin`, like the playback
settings), a full replacement, audited as `overlay_settings.update`, stored in `overlay_settings`
(migration 00028). They are not added to `playback_settings`, whose defaults are pinned to its table.
Off by default. Fields: `enabled`, `template`, `opacity` (0.05 to 0.8), `font_size_fraction` (0.015 to
0.1 of the video height) and `color` (`#RRGGBB`, upper case). The bounds keep the text legible but
unobtrusive, as ADR 0043 asks.

**The template is validated strictly, in the service and again by database constraints.** 1 to 120
characters, valid UTF-8, no control, format (so no bidi overrides or zero-width characters), separator or
private-use characters, none of `<`, `>`, `&`, and at least one placeholder. Any `{` or `}` left after the
three placeholders are removed is refused, so an unknown placeholder is an error and never reaches the
player, and no other substitution syntax can hide in the text. Quotes, `$` and `%` are allowed: the player
draws the template as text. The player must still never insert it as markup (the API says so).

**The session code is stored, not the trail's fingerprint.** The code is the first 40 bits of
`SHA-256("cipherframe/overlay/code/v1" 0x00 || session hash || tenant UUID)` in a 32-letter alphabet
without `0 1 I O` (eight characters). It is computed when the session is created and stored in
`playback_sessions.overlay_code` (indexed with the tenant), and `GET /v1/overlay-codes/{code}` (scope
`assets:read`, the trail's scope) returns the tenant's matching sessions: viewer ID, asset, auth method,
state, creation time and the trail's session fingerprint, so the trail can be read next.
The trail's existing fingerprint (8 hex characters of `SHA-256(session hash || tenant)`) is **not
reused**: it is computed in SQL in hex, so a code derived from it would need a scan of the trail's
partitions to be found, the trail may not hold a session whose events were dropped, and showing one
value in the player and another derivation in the trail would tie the code to the trail's format forever.
A separate, indexed code costs one column. A second, rarely colliding session is possible at 40 bits, so
the lookup returns a list (up to 20), never a guess.

**The code leaves with the trail.** The retention job (every five minutes, with the trail's window,
`CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`, default 90) sets `overlay_code` to `NULL` for sessions created
before the cutoff, in bounded batches. The session row itself is outside any window today (see ADR 0042),
so without this the code would keep a viewer traceable longer than the trail promises. The worker's
database role needs `UPDATE` on `playback_sessions`.

**The response carries `template` with the code already substituted, and the code separately.** The
player then substitutes only `{date}` and `{time}`, which it alone can know. `session_code` is also
returned for a support screen. `overlay` is absent when the overlay is off, and appears in the API-key
response and the browser (JWT and callback) response alike, because all paths end in
`playback.Service.CreateSession`. Existing sessions are not changed when settings change.

**The drift is `lissajous-v1`.** `seed` is the first 8 bytes of
`SHA-256("cipherframe/overlay/seed/v1" 0x00 || session ID text)` as 16 hex characters. It is one way and
uses a different domain string from the code, so neither reveals the other nor the session ID. From the
seed bytes `b`: frequencies `(kx, ky)` from six small pairs by `b[0] mod 6`, phases from `b[1..2]` and
`b[3..4]`. Position over time `t` (seconds since the response arrived): `u = 0.5 + 0.5 sin(2 pi kx t / 240 + px)`,
`v` likewise. The curve is closed with a 240 second period; its speed is at most `pi * 3 / 240` (about
0.039 of the room per second). Placement keeps the text box 2 percent of the frame away from every edge
for any text width. The full text is `spec/test-vectors/overlay/README.md`; the Go reference is
`internal/overlay`, and `drift.json` holds vectors that a Go test and an independent script both
reproduce (tolerance 1e-9, so other languages' sine implementations pass). An algorithm change needs a new
algorithm name.

**The viewer's clock supplies `{date}` and `{time}`**, as `YYYY-MM-DD` and `HH:MM:SS` in UTC. A viewer
can change their clock, which is one more reason the overlay is deterrence only.

## Consequences

- The overlay carries no personal data; tracing needs the tenant's own data and works only within the
  retention window.
- 40 bits is enough to find a session in one tenant, not to survive an adversary who reads a partly hidden
  code; the lookup says "no match" or lists several.
- `playback_sessions` gains a column and an index; every session creation reads one more settings row.
- Pinning `lissajous-v1` means players written against the vectors keep working. The player (M8) and the
  SDKs must test against `drift.json`.
- Not covered: removing the overlay from a recording (not possible to prevent), a brand logo or invisible
  watermark (M7-4 and v2.1), and cleaning the code on asset deletion (the retention window handles it).
