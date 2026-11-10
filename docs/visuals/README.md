# Visual explainers

Standalone pages for understanding how Cipherframe works. Open them directly in a browser; they need
no build step and no server. They are teaching aids, not specifications: example values (segment
length, quality ladder, bitrates, player thresholds) are illustrative until the matching gates are
decided (P8 encoding defaults, P13 reference player).

| Page | Shows |
|---|---|
| [recording-lifecycle.html](recording-lifecycle.html) | One recording from capture to ready-to-watch: resumable upload, probe, ladder without upscaling, aligned segments, encryption with a wrapped content key, playlists and the signed manifest. |
| [adaptive-playback.html](adaptive-playback.html) | How the player adapts quality to the network: fast start, the buffer as a shock absorber, a conservative throughput estimate, slow up-switching and fast down-switching, rescuing downloads that would stall, and the client-side overlay watermark. |

## Adaptive playback in short

Adaptation happens in the player. Cipherframe's job is to make it work well:

- a ladder that never upscales and uses quality-targeted encoding,
- segment boundaries at identical timestamps on every rendition, each starting with a keyframe, so
  switches are seamless,
- a master playlist that advertises each rendition's bitrate and resolution,
- tokens attached to every request and refreshed before they expire, so links last as long as the
  session,
- fast delivery from `edge` (proxy or presigned, with CDN support later).

## What these visuals do not show

They do not show the security limits. A viewer with a valid session can still record the screen or
reassemble segments; see [threat-model.md](../threat-model.md#out-of-scope).
