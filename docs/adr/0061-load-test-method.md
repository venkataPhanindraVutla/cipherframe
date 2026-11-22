# 0061. Load test method

- Status: Accepted (flagged for owner review)
- Date: 2026-11-22
- Gate: none (M9-4; choices ADR 0054 left open)
- Deciders: implementer

## Context

[ADR 0054](0054-operations-and-release-tooling.md) chose a small Go tool in the repository for the
load tests, using the generated API client, in both delivery modes, plus a transcode measurement.
It did not say how a virtual viewer behaves, what counts as "sustainable", or how the numbers are
kept honest. The results are published in [load-tests.md](../load-tests.md) and must be repeatable.

## Options considered

1. **Tool in the repository, shared client** (chosen, as in ADR 0054): `cmd/cipherframe-load`.
   The edge routes are not in the generated client (it covers the `api` tag only), so the tool
   uses `net/http` for playlists, key, segments, heartbeat and end, and the generated client for
   everything on the API.
2. **Viewer pacing:** fetch segments as fast as possible (measures raw throughput, not sessions);
   or one segment per segment duration (what a player does). Chosen: real-time pace, with an
   optional `--speed` factor that plays the same sessions faster.
3. **Stop rule:** a fixed viewer count; or ramp until a threshold breaks. Chosen: ramp in steps and
   stop at the first step that breaks a threshold, so a number is a measured knee, not a guess.
4. **Where the viewers' clip comes from:** real footage; or a generated test pattern. Chosen: a
   60 s FFmpeg `testsrc2` clip, so no one's footage is used and the input is reproducible.

## Decision

- **A viewer** creates a session, fetches the master playlist, one media playlist (`--rendition`,
  default the first listed), the key and the init segment, then one media segment per segment
  duration divided by `--speed`, with a random phase so viewers do not move in lockstep. It sends a
  heartbeat at the interval the server advertises (replaced by each heartbeat answer) and ends the
  session on exit. At the end of the clip it plays it again in the same session and refetches the
  media playlist (as a player would for fresh presigned URLs); it does not refetch the key.
- **A step** adds viewers, waits `--settle` (not measured), then measures for `--step-duration`.
  Latency is time to the last byte of the response. The tool sets the tenant's `delivery` setting
  through the API for the run (a full replace of the current values with only `delivery` changed).
- **Thresholds, documented in load-tests.md:** a step fails when segment p99 exceeds 1 s (a sixth of
  the 6 s segment, and well under a player's buffer) or when more than 1 % of requests fail. The
  number reported is the last passing step.
- **Output:** a raw CSV (`timestamp,viewer,kind,status,latency_ms`; the viewer is a local counter)
  holding every failure and a sample of successes, and a long-format summary CSV (per step and
  request kind: requests, errors, req/s, p50/p95/p99). Tokens, session IDs, keys and URLs are
  never written. The API key comes from `CIPHERFRAME_API_KEY` or `--api-key-file`, never a flag
  value.
- **Transcode:** the file is uploaded `--jobs` times, `--concurrency` at a time; each job is timed
  from the commit response to the first poll (every 250 ms) that sees `ready`. Throughput is media
  seconds of finished jobs per wall-clock second over the whole run, uploads included.
- **CPU limits** are set with `docker update --cpus` on the container that runs the role under test.
- **CI:** `deploy/compose/load-smoke.sh` runs a 2 viewer, 20 second play and a one-job transcode
  against the compose stack, after the CLI end to end step. Unit tests cover the ramp, the
  percentiles, the threshold check and the playlist parsing.
- **No new dependency.** The tool uses the standard library and `internal/apiclient`.

## Consequences

- Numbers are laptop numbers from Docker Desktop's VM and from a load generator sharing the same
  machine. They bound a design, not a production deployment.
- `presigned` offloads segment bytes to the object store, so its figure measures the storage
  service (SeaweedFS, one process) plus the edge's playlist and key work, not the edge alone.
- `--speed` multiplies segment traffic but not heartbeats or key fetches, so a speed-up row stands
  for the same count of real-time viewers only as far as segment bytes go. The published tables
  are real-time (`--speed 1`) except one labelled run.
- The generator runs inside the compose network (sharing the storage container's network namespace),
  because Docker Desktop's published-port forwarding capped a first attempt at a few hundred viewers
  while the edge was nearly idle. The cost is that the generator shares the VM's CPUs with the
  service under test.
- Revisit when the edge gains a cache or a CDN is put in front, or when a second storage backend is
  measured.
