# 0064. HEVC and AV1 renditions

- Status: Accepted
- Date: 2026-11-23
- Gate: P18
- Deciders: project owner

## Context

M10-3 adds optional HEVC and AV1 renditions, off by default: a multi-codec master playlist with
codec signalling, player capability negotiation, and documented storage and purge implications.
ADR 0024 fixed H.264 in CMAF/fMP4 with AES-128 applied by the worker, a GPL FFmpeg, and H.264
patent licensing as the operator's concern. ADR 0063 adds hardware encoders.

## Options considered

- **Codecs:** HEVC and AV1; AV1 only; HEVC only.
- **Negotiation:** one master playlist with CODECS attributes, the player choosing; edge filtering
  variants from capabilities the player declares; a separate master playlist per codec.
- **Enablement:** a per-tenant setting; an operator-wide setting; a per-upload option.

## Decision

**Codecs and encoders**

- HEVC and AV1, each as an optional extra next to H.264. H.264 always keeps its full ladder, so
  every player has something it can decode.
- Software encoders: libx265 for HEVC (GPL-2.0-or-later, consistent with the already-GPL FFmpeg
  build) and SVT-AV1 for AV1 (BSD-3-Clause-Clear with the AOM patent licence). Hardware encoders
  from ADR 0063 are used where they support the codec (`hevc_nvenc`, `av1_nvenc`, `hevc_vaapi`,
  `av1_vaapi`, `hevc_qsv`, `av1_qsv`, `hevc_videotoolbox`; VideoToolbox has no AV1 encoder, so AV1
  falls back to SVT-AV1 there).
- Each enabled codec gets the full ladder, because players do not switch codec families reliably
  in the middle of playback, so a partial ladder would strand viewers on a bad network. Keyframe
  placement, segment length and per-rung caps follow ADR 0024, with lower bitrate caps per codec
  tuned on fixtures with VMAF and recorded.
- Packaging is unchanged: CMAF/fMP4, encrypted per segment with AES-128 by the worker. HEVC uses the
  `hvc1` sample entry, which Apple players require; AV1 uses `av01`.

**Negotiation: one master playlist**

- One master playlist lists every variant with an accurate `CODECS` attribute, derived from the
  encoded stream's profile and level rather than hard-coded. H.264 variants come first, so a
  player's starting variant is always decodable. hls.js and Safari drop variants they cannot decode.
- No new API field. The reference player is tested against the multi-codec playlist.

**Enablement: per tenant**

- A tenant setting, `extra_codecs`, lists any of `hevc` and `av1`; it is empty by default and applies
  to uploads made after it changes. Existing assets are not re-encoded.
- Workers record the encoders their FFmpeg provides when they start. The settings endpoint refuses a
  codec that no worker has reported, and a job whose worker lacks an encoder fails that codec's
  renditions with a recorded reason while the H.264 ladder still completes.

**Licensing**

- HEVC patent licensing, like H.264's, is the operator's concern; the docs say so. AV1 is offered
  under the AOM royalty-free patent licence. The shipped worker image stays GPL as a separate
  process (I1).

## Consequences

- Each enabled codec adds a full ladder: more storage (measured on fixtures and documented) and more
  transcode time. SVT-AV1 in software is much slower than libx264; the documented throughput says
  how much.
- All renditions live under the asset's delivery prefix and are covered by the integrity manifest,
  verification, deletion and the CDN purge (ADR 0062), so those paths need no special cases.
- With the setting empty, the master playlist and renditions are the same as before, which the tests
  check.
