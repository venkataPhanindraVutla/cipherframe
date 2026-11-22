# 0052. Reference player implementation choices

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M8-2)
- Deciders: implementer; the owner reviews the choices below

## Context

ADR 0050 fixed the form (a framework-free `<cipherframe-player>` on hls.js), the controls and the
tooling (Vite, Vitest, Playwright). The brief left the details open: how the token reaches each request,
how it is refreshed, when the player stops, how the overlay is positioned, and which checks run. These are
those details.

## Decisions

**Token on every request.**

- Header mode (the default): hls.js `xhrSetup` adds `Authorization: Bearer <current token>`. The poster,
  the thumbnail track and the sprite are fetched with the same header and shown through object URLs, so
  no URL carries the token.
- URL mode is detected from the URLs the edge hands out: a `t` parameter on `manifest_url` (the response's
  `token_transport` is not trusted over the URL). The player then sends no header (the edge refuses both
  forms, ADR 0030) and a small hls.js loader subclass sets `t` to the *current* token on each request, so
  playlists fetched after a refresh do not reuse the token baked into an older playlist.
- The token is attached only to URLs on the manifest's origin under the session's directory
  (`/v1/play/<id>/`). With `presigned` delivery (ADR 0032) segments come from storage: the token and
  `Authorization` header never go there, where a header would also break the presigned signature.

**Refresh is the heartbeat.** The API has no separate refresh route: `POST /v1/play/{id}/heartbeat`
returns a new token (spec/openapi.yaml). The player heartbeats on the session's interval, swaps the token
atomically, and heartbeats sooner when the interval is longer than 80 percent of the token's remaining
life. A `429` waits for `Retry-After`; a network error retries after 5 seconds. Each refresh emits
`cipherframe:tokenrefresh` (no token in the event), so a host that wants its own bookkeeping can follow it.
The player also heartbeats when the tab becomes visible again.

**Stop.** A `401` or `403` from the edge (a playlist, the key, a segment or a heartbeat) stops the player at
once: loading stops, hls.js is destroyed, the video pauses, the controls are disabled and the `state`
attribute and a status message say why. The edge's answer is deliberately generic, so the label comes from
the clock: after the token's expiry it is `expired`, before it `revoked`. The session's maximum age also
stops it as `expired`. `end()` stops it as `ended`. Each stop emits `cipherframe:stop` with the reason.
Other fatal hls.js errors get three retries and then the `error` state. No automatic new session is
started: the host's backend decides that.

**End on leaving.** `pagehide` and removal of the element call `POST /end` with `fetch(..., {keepalive:
true})` and the token header (a beacon cannot set it). A hidden tab does not end the session; the heartbeat
keeps it alive. A page that is restored from the back-forward cache shows the `ended` state.

**Controls use native elements.** Play is a button, the seek bar is `<input type="range">`, and speed,
quality and subtitles are `<select>` menus. They are keyboard accessible, announced by screen readers and
styleable without a menu library; the cost is that the menus look like the platform's. The seek bar's hover
preview is a plain div over the sprite sheet. Fullscreen applies to the player's wrapper, not the video,
so the overlay stays in the picture. Styling is by `--cf-*` custom properties and `::part()`. Motion is
limited to a 150 ms colour change on controls, and only without `prefers-reduced-motion: reduce`; the
overlay moves in one-second steps, never animated.

**Overlay.** The template is filled in UTC each second and assigned with `textContent`. The overlay layer
is sized to the rectangle the picture covers inside the `object-fit: contain` box (re-measured on resize,
metadata and fullscreen), so the text stays at least `margin` inside the picture, never on the letterbox.
The box width and height are measured from the text as drawn at `font_size_fraction` of the picture's
height, as the algorithm requires. `lissajous-v1` is implemented from the spec and checked against every
vector of `drift.json` within the stated tolerance. A color that is not `#RRGGBB` falls back to white and
opacity is clamped to the documented range. Deterrence only: a viewer who controls the page can remove it.

**Safari.** Without Media Source Extensions hls.js cannot run. There the player uses native HLS only in URL
mode and otherwise shows the `error` state with the reason (ADR 0050). Not tested in CI.

**Checks.** `tsc --noEmit` with `strict`, `noUncheckedIndexedAccess`, `noUnusedLocals` and
`noUnusedParameters` is the lint: the code is small, and a type check catches what matters without ESLint's
configuration and its dependency tree. Add ESLint if the package grows or gets contributors who want style
rules. Unit tests use Vitest with jsdom and a stand-in for hls.js where the player is built; the drift
vectors are read from `spec/test-vectors/overlay/drift.json` itself, so a change to the spec fails the test.

**End-to-end test.** CI job `player` starts the compose stack (server and worker), bootstraps a key like the
`compose` job, generates a 40 second video with the test-only FFmpeg that the `media` job also exports
(the shipped FFmpeg has no test sources), uploads it with `curl` (one multipart part) and polls to `ready`.
The Playwright test sets the tenant's playback settings to a 60 second token and a 10 second heartbeat (the
lowest the API allows), adds the demo origin to `allowed_origins`, enables the overlay, then asserts:
`currentTime` advances, the key request carried `Bearer <token>`, the second heartbeat carries a different
token while playback continues, and after `POST .../revoke` the state becomes `revoked`. The trace is kept
on failure and uploaded.

**Pins and licences.** hls.js 1.7.4 and every tool are pinned to exact versions (`save-exact`), with
`pnpm-lock.yaml` committed, and the CI install is `--frozen-lockfile`. The only runtime dependency is hls.js
(Apache-2.0), bundled into the library file. Everything else is development only: MIT for most (Vite,
Vitest, jsdom, their dependencies), Apache-2.0 (TypeScript, Playwright), BSD, ISC, BlueOak-1.0.0 and MPL-2.0
(`lightningcss`, a Vite build dependency that is not shipped). `pnpm licenses list` produced this list.

## Consequences

- The player package is not yet published; `private: true` stays until v2.0.0 (M11).
- The bundle holds hls.js (about 750 kB before compression, 206 kB gzipped). A host that already ships
  hls.js cannot share it yet; revisit when the package is published (externalise it as a peer dependency).
- Playback cannot continue after the token's expiry: the edge refuses an expired token for the heartbeat
  too, so a player that was suspended (a laptop lid) longer than the token lifetime needs a new session.
- Browser coverage in CI is Chromium only (ADR 0050).
