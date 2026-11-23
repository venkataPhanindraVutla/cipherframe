# 0067. HEVC and AV1 implementation

- Status: Accepted (flagged for owner review)
- Date: 2026-11-23
- Gate: none
- Deciders: none (implementation choices under ADR 0064, for the owner to review)

## Context

ADR 0064 chose HEVC and AV1 as optional extras beside H.264 (libx265 and SVT-AV1, a full ladder per codec,
one master playlist with accurate `CODECS`, a per-tenant `extra_codecs` setting that workers' reported
encoders gate). It left open where the setting is stored and when it is read, how a worker reports what it
can encode, how the extra renditions are made and named, what a failed codec leaves behind, how the master
playlist is ordered, which quality settings to start from, and what the build needs. This ADR records those
choices and the measurements behind the numbers (see [codecs.md](../codecs.md)).

## Decisions

**The setting.** `extra_codecs` is a column of `playback_settings` (an array of `hevc` and `av1`, empty by
default) and a field of `PUT /v1/playback-settings`, which is a full replacement, so like every other field
it is required: a client that does not send it gets the usual "is required" field error. Turning a codec on
is refused with `invalid_request` and the field `extra_codecs[i]` when no worker has been seen within the last
5 minutes that reports it. A codec the tenant already has on is not checked again, so the other settings can
still be changed while the workers are down; only emptying or keeping the list never needs a worker. An
unknown or repeated entry is a field error of its own.

**Snapshot at upload.** The setting is copied onto the asset when it is created (`assets.extra_codecs`), not
read again when processing starts. "Applies to uploads made after it changes" then holds exactly, including for
an upload that waits in the queue, and a retried job makes the same codecs as the first attempt. The asset
reports it as `extra_codecs.requested` in the API, with `extra_codecs.failed` (below). The `extra_codecs`
member is absent for an asset made with the setting empty, so such an asset reads as before.

**How a worker reports.** At startup the worker reads FFmpeg's `-encoders` list and keeps the extra codecs it can
encode: the software encoder (`libx265`, `libsvtav1`) or the selected hardware encoder (`hevc_nvenc`, ...) is in
the list, because a failing hardware encode is repeated in software (ADR 0066). The startup capability check
does not require them: an operator's own FFmpeg may lack them, and the worker then makes H.264 only. Each worker
process writes one row of `worker_capabilities` (a fresh random ID, the codecs, when it started and when it last
reported) at startup and again every minute, and removes rows that were last seen more than a day ago. The
settings endpoint counts a row seen within 5 minutes. A table row per process was chosen over a row per codec or
a counter because it needs no coordination between workers and goes stale by itself when a worker dies.

**One FFmpeg run per codec, after H.264.** The H.264 run is unchanged (poster, sprite sheet and all). Each
extra codec is a further FFmpeg run over the same source with the same logo, into its own directory, with that
codec's full ladder. One process for everything would have shared the decode, but a failed AV1 encode would
then have failed the H.264 ladder with it, which ADR 0064 rules out; the decode is a small part of the work next
to a software AV1 or HEVC encode. The runs go one after another in the job (workers are sized by FFmpeg's use of
every core), the job's time limit is raised to allow one transcode timeout per codec, and each run has its own
timeout. A run that cannot be made is not an error of the job. The transcode minutes quota (ADR 0047) still
counts the source's minutes once, not once per codec.

**Names.** A rendition of an extra codec is named after the H.264 one with the codec added: `720p_hevc`,
`720p_av1`. Those fit the existing rendition name rule (1 to 16 characters from `[a-z0-9_]`), so the object
keys, the artifact registry, the integrity manifest, re-key, verification, deletion and the CDN purge (by
prefix) need no case of their own; tests cover each. H.264 names are unchanged.

**Failures are recorded, not fatal.** The reasons are fixed codes: `encoder_unavailable` (the worker's FFmpeg
has no encoder for it), `transcode_failed`, `transcode_timeout`, and `output_invalid` (missing files, a codec
configuration the codec string cannot be read from, or segments that do not match the H.264 ladder's in count
and duration). They are written to `assets.extra_codec_failures` in the transaction that makes the asset
`ready`, shown as `extra_codecs.failed` in the API, logged without detail beyond the error, and counted in
`cipherframe_extra_codec_failures_total{codec,reason}`. Only an interrupted job (shutdown, deadline) is retried
whole. The masked variant gets the same codecs from the masked file; if one of those fails the cause is logged and
counted, and the codec is simply absent from the masked variant's manifest. The asset's record describes the
original variant, which is the one that is `ready` first.

**The manifest.** The rungs of the extra codecs are listed with the H.264 rungs, each with the optional members
`codec`, `video_codec` (the encoder, such as `libx265` or `hevc_nvenc`) and `preset`, which are absent for
H.264 rungs, so a manifest of an asset made without extra codecs is byte for byte what it was and an older
verifier that ignores unknown members still verifies it. Every rendition of every codec is in the Merkle trees
and the top-level root like any other.

**The master playlist.** Variants are listed by codec family, H.264 first, then HEVC, then AV1, and by bandwidth
within a family, so the first entry is always decodable; the order with H.264 alone is the old order. `CODECS` is
read from the init segment: the `hvcC` box for HEVC (`hvc1.1.6.L120.90`) and the `av1C` box for AV1
(`av01.0.08M.08`), like `avcC` for H.264, never from the encoder settings. Edge's session rewriting is line based
and handles the new names unchanged; subtitles groups are added per variant line as before.

**Same timestamps.** Every codec cuts at the same frames: keyframes every 2 seconds at the same times (forced,
IDR, no scene-cut keyframes), the same segment durations (checked against the H.264 ladder, a mismatch is
`output_invalid`). The encoders differ in how many frames they hold back for reordering, which moves the first
picture inside the container (H.264 with B-frames: two frames in; SVT-AV1: none). So that the renditions
present together, the worker reads where the H.264 ladder presents its first picture (`media.FirstVideoPTS`,
from the first segment's `moof`) and starts each extra codec's output the same distance in
(`-output_ts_offset`). Video presentation times then match to the millisecond in all twelve renditions of a
three-codec ladder, as tests check. What is left: audio segments of different codecs can start up to three AAC
frames (64 ms) apart, because the HLS muxer cuts at the video packet's decode time, which differs by the
reordering delay; within one codec they are identical. A player does not change codec family in the middle of a
stream, so this is not visible in playback. When the H.264 start cannot be read the extra codec keeps its own
start (a warning is logged), and a codec that reorders more than H.264 (x265 against an operator's `ultrafast`
x264) cannot be moved earlier, so its start stays a frame or two later.

**Quality settings.** Software only, from the measurements in codecs.md on the two fixtures (VMAF against the
source scaled to the rung's size, default model):

| | H.264 | HEVC | AV1 |
| --- | --- | --- | --- |
| Encoder | libx264, operator preset (default medium) | libx265, preset `medium` | libsvtav1, preset `8` |
| Constant quality | CRF 23 | CRF 26 | CRF 35 |
| Caps per rung (1080, 720, 480, 360, 240) | 4500, 2500, 1200, 700, 350 kbps | 2700, 1500, 720, 420, 210 kbps (0.6x) | 2700, 1500, 720, 420, 210 kbps (0.6x) |
| Keyframes | `-g` 2 s, `-keyint_min`, no scene cut, IDR | same, `scenecut=0:open-gop=0` | same, `scd=0:irefresh-type=2` |
| Sample entry | `avc1` | `hvc1` | `av01` |

The sweep over CRF, preset and cap is in codecs.md. In short: x265 CRF 26 spends 15 to 52 per cent fewer bits than
x264 CRF 23 for 0.6 to 3.9 VMAF points less (parity is about CRF 25 and 22 to 23); SVT-AV1 CRF 33 is at parity
with x264 CRF 23 and CRF 35 gives up 0.5 to 1.2 points for 18 to 21 per cent fewer bits. SVT-AV1 preset 8 costs
about as much CPU time as x264 medium (preset 6 doubles it for 16 per cent fewer bits, presets 10 and 12 are 30
per cent cheaper and noticeably worse), and x265 `medium` costs 1.1 to 2.1 times as much. Both codecs' caps are 0.6
of H.264's, not 0.5 for AV1: SVT-AV1 sits under its cap anyway, and 0.5 cost 1.3 more VMAF points on the hardest
fixture for a 6 per cent saving on the easy one. The ladders (20 s, 1080p source, 4 CPUs in a linux/arm64
container) are 0.61 to 0.68 (HEVC) and 0.54 to 0.72 (AV1) of the H.264 ladder's bytes, and take 1.3 to 2.1 and
1.2 to 1.5 times as long as the H.264 run. The 1080p rung (2.6 to 5 VMAF points less than H.264) and the 720p rung of a hard source (2.9 for HEVC, 5.0 for
AV1) lose most: the cap binds, or SVT-AV1's capped CRF stays under it; every other rung is within 1.2. These
are starting points measured on two synthetic sources on one ARM machine, not tuned on camera footage.

The extra codecs' presets are not operator settings (the libx264 preset is, ADR 0038): a preset is a trade of
speed for size that an operator may want per codec, which is for a later release if anyone asks. VideoToolbox has no
AV1 encoder, so AV1 under it is SVT-AV1 in software. The hardware encoders get the same arguments as their H.264
ones with the codec's own CRF as the quality value; they are as unverified as the H.264 ones (docs/hardware-encoders.md).

**The build.** libx265 4.1 (GPL-2.0-or-later, from the VideoLAN mirror) and SVT-AV1 v3.1.2 (BSD-3-Clause-Clear with
the AOM patent licence) are compiled from sources pinned by SHA-256 in `build/worker.Dockerfile` and are in both
worker image targets, whose FFmpeg additionally has the NVENC, VAAPI and QSV encoders of HEVC and AV1 in
`worker-hw`. x265 is built 8-bit only (every rendition is 8-bit 4:2:0), so a 10-bit HEVC rendition is not
possible. Two details of the static aarch64 link are in the Dockerfile's comments: x265's pkg-config file needs a
version and loses the shared `libgcc_s`, and with these libraries a position-independent static link overflows the
GOT range of the glibc `libm.a`, so the static FFmpeg and x265 are built without PIC. SVT-AV1 3.1.2 rather than the
newer 4.x line because it is the version built and run against this FFmpeg here; 4.x was not tried. `SOURCE.md` and the
licence texts of the image list both libraries; HEVC patent licensing is the operator's concern, as H.264's is. A
`measure` build target (never shipped) adds libvmaf (BSD-2-Clause-Patent) for the numbers in codecs.md.

**The reference player.** It has no codec setting. hls.js drops the variants the browser cannot decode (it asks
`MediaSource.isTypeSupported` for each `CODECS` string) and starts on a decodable one, which a unit test
(`player/test/multicodec.test.ts`, the real hls.js over a fixture master with `MediaSource` stubbed) and the
end-to-end test (CI prepares an asset with both codecs, and Chromium plays it) check. Chromium in CI is only
assumed to decode H.264 and AV1. The end-to-end test was run against the compose stack built from this branch (a worker
image with both codecs, an asset with both on): the master played in Chromium and the new test passed.

## Consequences

- A tenant with both codecs stores about 2.2 to 2.4 times what H.264 alone needed, and a worker spends 3.5 to 4.6
  times as long on one upload (codecs.md has the numbers per codec and rung). An operator who
  keeps a worker's CPU for H.264 can leave the codecs off and loses nothing.
- Adding the codec setting to `PUT /v1/playback-settings` makes it required: a client written before M10-3 that
  sends the full replacement it got from an older `GET` gets a field error until it adds `extra_codecs`. The same
  rule held for each earlier setting, and the player's end-to-end test (which reads the settings and writes them
  back) and the contract tests were updated.
- A worker that cannot run for a long time leaves its row, which expires from the 5 minute window: a tenant can
  keep an enabled codec while no worker can make it, and each new upload then records `encoder_unavailable` until
  one is back.
- Failures of the masked variant's extra codecs are not on the asset. If that matters, add a second column or make
  the asset's record per variant.
- A job with both codecs can take several times as long as an H.264-only job and holds a media slot all that time.
  The per-job timeout is the sum of the transcode timeouts, so a stuck codec costs one timeout, not the job.
- Not done: re-encoding existing assets for a newly enabled codec, a codec choice in the API or the player,
  per-codec presets, 10-bit or HDR renditions, and any measurement of the hardware HEVC and AV1 encoders.
