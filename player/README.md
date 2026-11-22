# Cipherframe reference player

`<cipherframe-player>`: a framework-free custom element, written in TypeScript on hls.js, that plays one
Cipherframe playback session. Design choices: [ADR 0050](../docs/adr/0050-reference-player-approach.md) and
[ADR 0052](../docs/adr/0052-reference-player-implementation.md).

**Your backend creates the session. The API key never goes in the browser.** The browser only ever holds the
session's short-lived token.

## Use

```ts
import "@cipherframe/player"; // registers <cipherframe-player> (build: pnpm build, file dist/cipherframe-player.js)

const player = document.querySelector("cipherframe-player")!;
// `session` is the JSON your backend got from POST /v1/playback-sessions, passed through unchanged.
player.load(session); // or: player.session = session
```

The tenant must list your page's origin in `allowed_origins` (`PUT /v1/playback-settings`), or the browser
blocks the edge's answers.

The session needs `manifest_url` and `token`; `token_expires_at`, `heartbeat_interval_seconds`,
`session_expires_at` and `overlay` are used when present.

### What it does for you

- **Token on every request:** playlists, key and segments, in `Authorization: Bearer ...`. When the tenant
  uses `token_in_url` (a `t` parameter on `manifest_url`) it sends `?t=` instead, never both. The token is
  attached only to the session's edge URLs, never to presigned storage URLs.
- **Heartbeat and refresh:** `POST /v1/play/{id}/heartbeat` on the session's interval. The answer carries the
  next token, which every later request uses. There is no separate refresh route.
- **Stop:** a `401` or `403` from the edge, the end of the session, or `end()` stops loading and shows the
  state. **End:** the player calls `POST /end` when the page hides (`pagehide`) or the element is removed.
- **Overlay:** the session's `overlay` object is drawn over the picture as plain text, with `{date}` and
  `{time}` filled in UTC every second, drifting along `lissajous-v1`. It stays inside the picture, also in
  fullscreen.

> **The overlay is deterrence only.** It makes a recording traceable and hard to crop. Anyone who controls
> the page or the player can remove it ([ADR 0048](../docs/adr/0048-overlay-watermark-policy.md)).

### Controls

Play and pause, a seek bar with thumbnail preview on hover (needs `thumbnails.vtt` and `sprite.jpg`; older
assets have none and show no preview), quality (Auto and the renditions), speed, subtitles (the session's
subtitle tracks) and fullscreen. The poster is `poster.jpg` fetched with the token. Keyboard: Tab to the
controls; on the video, Space or K plays and pauses and the arrow keys seek 5 seconds; the seek bar and menus
use the native keys. All controls have ARIA labels and a visible focus ring.

### API

| Member | |
|---|---|
| `load(session)`, `session = ...` | Start playing a session (replaces any current one). |
| `end()` | End the session at the edge and stop. Returns a promise. |
| `state` (also the `state` attribute) | `idle`, `loading`, `playing`, `paused`, `expired`, `revoked`, `ended`, `error`. |
| `video` | The inner `<video>`. |

### Events

All bubble and are composed. None carries a token.

| Event | `detail` | When |
|---|---|---|
| `cipherframe:ready` | `{levels, subtitles}` | The master playlist was parsed. |
| `cipherframe:tokenrefresh` | `{expiresAt}` | A heartbeat returned a new token. |
| `cipherframe:stop` | `{reason: "expired" \| "revoked" \| "ended"}` | Playback stopped for good. Start a new session through your backend to play again. |
| `cipherframe:error` | `{message}` | An error that is not a stop (unsupported browser, bad overlay config, fatal playback error). |

The edge answers every refused request with the same `401`, so `expired` versus `revoked` is decided by the
clock: a refusal after the token's expiry is `expired`.

### Styling

Custom properties on the element: `--cf-bg`, `--cf-fg`, `--cf-accent` (seek bar), `--cf-focus` (focus
ring), `--cf-control-bg`, `--cf-controls-bg`, `--cf-radius`, `--cf-font`. Parts for `::part()`: `container`,
`video`, `overlay`, `overlay-text`, `status`, `controls`, `play`, `time`, `seek`, `preview`, `speed`,
`quality`, `subtitles`, `fullscreen`. The element is 16:9 by default; set `aspect-ratio` or a size. Motion is
limited to a short colour change and is off with `prefers-reduced-motion: reduce`.

### Browser support

Browsers with Media Source Extensions (Chrome, Edge, Firefox, Safari 17.1+ and iPadOS) through hls.js. CI
tests Chromium. **Safari without Media Source Extensions** (iPhone Safari before 17.1) plays HLS natively,
and native HLS cannot add headers: it works only when the tenant enables `token_in_url` ([ADR
0030](../docs/adr/0030-playback-token-transport.md)); otherwise the player shows an error state. Native Safari
playback is not covered by CI.

## Develop

Node 24 and pnpm (the version is pinned in `package.json`).

```sh
pnpm install --frozen-lockfile
pnpm typecheck     # tsc --noEmit, strict
pnpm test          # Vitest: token, refresh, stop, overlay, drift vectors, menus
pnpm build         # dist/cipherframe-player.js (ESM) and the type declarations
pnpm build:demo && pnpm preview:demo   # the demo page on http://localhost:4173
```

The drift tests read `spec/test-vectors/overlay/drift.json`, so run them from this directory.

### End-to-end

Needs the development stack running with the worker (`docker compose -f deploy/compose/compose.yaml
--profile worker up -d --wait server worker`), a bootstrapped API key, and the test-only FFmpeg that
`build/worker.Dockerfile --target tools` exports (CI does exactly this in the `player` job).

```sh
export CIPHERFRAME_API_KEY=...      # from `server admin bootstrap`; never pass it as an argument
export FIXTURE_FFMPEG=out/tools/ffmpeg-fixtures
export CIPHERFRAME_ASSET_ID="$(sh e2e/prepare-asset.sh)"
pnpm exec playwright install chromium
pnpm e2e
```

The test changes the tenant's playback and overlay settings (60 second token, 10 second heartbeat, overlay on):
use a throwaway tenant.
