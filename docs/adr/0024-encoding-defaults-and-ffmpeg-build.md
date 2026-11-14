# 0024. Encoding defaults and FFmpeg build

- Status: Accepted
- Date: 2026-11-11
- Gate: P8
- Deciders: project owner

## Context

M3 transcodes untrusted uploads into encrypted adaptive HLS. The plan requires CMAF/fMP4 packaging,
keyframe-aligned segments across renditions (pitfall 4), quality-targeted encoding for low-motion
talking-head content (pitfall 11), FFmpeg and FFprobe as separate processes (I1), and a stated
licensing position for the FFmpeg the project ships. FFmpeg's HLS muxer cannot apply AES-128 to fMP4
segments.

## Options considered

- Segments: 6 s CMAF/fMP4; 4 s CMAF/fMP4; 6 s MPEG-TS.
- Ladder: five rungs with capped CRF; four rungs capped at 720p; a fixed-bitrate ladder.
- Encoder and licensing: libx264 in a GPL FFmpeg; OpenH264 in an LGPL FFmpeg; no bundled FFmpeg.
- FFmpeg source: a minimal build from pinned source; a pinned static build; the Debian package.

## Decision

**Packaging**

- CMAF/fMP4 HLS with **6 s** segments and a **2 s** keyframe interval (closed GOPs, scene-cut
  keyframes disabled so cuts land on identical timestamps on every rendition).
- FFmpeg writes unencrypted fMP4; Cipherframe encrypts each segment with AES-128 **in-process** while
  uploading, so plaintext segments and keys never touch disk or storage.

**Ladder and rate control**

- Five rungs: 1080p, 720p, 480p, 360p, 240p. A rung is used only if the source is at least that
  tall; resolution and bitrate are decided separately (a low-bitrate source still gets every rung its
  resolution allows).
- H.264 High profile, capped CRF (starting point CRF 23) with per-rung `maxrate`/`bufsize` caps of
  about 4.5, 2.5, 1.2, 0.7 and 0.35 Mbps. AAC-LC 96 kbps stereo.
- Size and VMAF are measured on fixture media in tests; exact CRF and caps are tuned during M3 and
  recorded in a follow-up ADR if they move materially.

**Encoder, licensing and configurability**

- The worker image ships an FFmpeg built with **libx264**, which makes that FFmpeg binary GPL. It is
  invoked only as a separate process (I1), so Cipherframe's own code stays Apache-2.0. The image
  includes FFmpeg's licence texts and a written source offer (the exact source and build script are in
  the repository).
- Operators can use **their own FFmpeg and FFprobe** instead: `CIPHERFRAME_FFMPEG_PATH` and
  `CIPHERFRAME_FFPROBE_PATH` select the binaries. At startup the worker checks that the configured
  binaries run and provide the encoders, muxers and filters it needs, and refuses to start otherwise.
- H.264 patent licensing is the operator's concern; the docs say so.

**FFmpeg build**

- FFmpeg 9.0.2 is built from pinned source (verified by checksum) in the worker image's Dockerfile,
  with `--disable-everything` and only the protocols, demuxers, decoders, parsers, filters, encoders
  and muxers Cipherframe needs: MP4/MOV, WebM/Matroska input; H.264, HEVC, VP8, VP9, AV1, AAC, Opus
  and MP3 decoding; libx264 and AAC encoding; fMP4/HLS output. Network protocols are disabled; only
  `file` and `pipe` remain.

## Consequences

- A minimal FFmpeg narrows the attack surface for untrusted uploads; uncommon input formats are
  rejected at probe time with a clear error.
- Image builds are slower (FFmpeg and x264 compile in the build stage); CI caches the stage.
- Distributing a GPL FFmpeg binary carries GPL obligations for the worker image only; operators who
  want to avoid them can supply their own FFmpeg.
- Encrypting in-process means the worker, not FFmpeg, touches the content key, and segments are
  buffered per segment (6 s is small); this is the same constraint the plan's integrity hashing needs.
- Note, 2026-11-14: the 6 s rule is a target, not a guarantee for the last segment. A final segment
  shorter than 1 s is merged into the previous one (so the last segment can be up to about 7 s), and
  each output is capped at the video duration (`-t`) so longer audio cannot create such a tail. See
  [architecture.md](../architecture.md).
- HEVC/AV1 output, hardware encoders and other codecs remain M10 decisions (P17, P18).
