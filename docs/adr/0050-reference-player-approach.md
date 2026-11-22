# 0050. Reference player approach

- Status: Accepted
- Date: 2026-11-22
- Gate: P13
- Deciders: project owner

## Context

M8-2 builds a reference player in TypeScript that plays protected Cipherframe sessions. It
attaches the token to every request (pitfall 5), keeps the session alive with heartbeats and
refreshes, stops cleanly on expiry or revocation, and draws the overlay watermark (ADR 0048). In
v2.0.0 it becomes the npm `player` package. The plan left its form, its controls and its tooling
open.

## Options considered

- **Form:** a framework-free web component; a React component; a plain TypeScript library with no
  user interface.
- **Controls:** the plan's list plus the poster and seek-bar thumbnails (M7-2); the plan's list
  only; a minimal set.
- **Tooling:** Vite, Vitest and Playwright; esbuild, Node's test runner and Playwright.

## Decision

- **Form:** a framework-free custom element, `<cipherframe-player>`, written in TypeScript on
  hls.js. It works in any page or framework, and it becomes the v2 npm `player` package as it is.
- **Controls:** play and pause, seek, quality, speed, fullscreen, subtitles and the overlay
  watermark (the plan's list), plus the poster and thumbnail previews on the seek bar.
- **Tooling:** Vite in library mode for the bundle and a demo page, Vitest for unit tests and
  Playwright for the end-to-end test, which runs against the development stack in CI.

## Consequences

- The repository gains a TypeScript toolchain (Node, pnpm) in `player/` and a CI job for it.
- Integrators style the player through CSS custom properties and parts, not framework props.
- Browser coverage in CI is Chromium through hls.js. Safari's native HLS cannot add headers to
  requests, so Safari relies on hls.js where Media Source Extensions exist and otherwise on the
  per-tenant `token_in_url` setting (ADR 0030); this is documented rather than tested in CI.
