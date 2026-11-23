# 0066. Hardware encoder implementation

- Status: Accepted (flagged for owner review)
- Date: 2026-11-23
- Gate: none
- Deciders: none (implementation choices under ADR 0063, for the owner to review)

## Context

ADR 0063 chose four hardware encoders per worker, a startup test with software fallback, a per-job
retry, and a build with `nv-codec-headers`, `libva` and `libvpl`. It left open how those fit the
existing worker: one FFmpeg process makes the whole ladder, the shipped FFmpeg is static and has no
test-pattern sources, and the only hardware to measure on is an Apple Silicon Mac whose FFmpeg (6.0) is
older than the one the project builds.

## Decisions

**Settings.** `CIPHERFRAME_WORKER_ENCODER` is `software` (default), `nvenc`, `vaapi`, `qsv` or
`videotoolbox`; anything else stops the worker at startup. `CIPHERFRAME_WORKER_HW_DEVICE` (default
`/dev/dri/renderD128`) is the render node VAAPI and QSV open. It must be a plain path under `/dev`:
the value goes into FFmpeg's `-init_hw_device` option syntax, where `:`, `,` and `=` mean something.

**One mapping.** `internal/media/encoder.go` holds the only mapping from (encoder, codec, rung) to
FFmpeg arguments. `codec` is a parameter that accepts only `h264` today, so M10-3 adds cases to one
switch. libx264's arguments are unchanged byte for byte (the existing tests pass untouched).

**Where the hardware starts.** Decode, scale, the logo and the masker's output stay in software.
The end of each rendition's filter chain becomes `format=nv12,hwupload` for VAAPI and QSV (with
`-init_hw_device` and `-filter_hw_device` before the input; QSV derives from a VAAPI device on the
same render node) and stays `format=yuv420p` for NVENC and VideoToolbox, which read system memory.
The poster and sprite sheet are JPEGs made in software for every encoder.

**Constant quality.** The ladder's CRF 23 is passed as the quality value of each encoder's own
constant-quality mode, unchanged: `-rc vbr -cq 23 -b:v 0` (NVENC), `-rc_mode QVBR -global_quality 23`
(VAAPI, the mode that still honours a bitrate cap), `-global_quality 23` with `-look_ahead 0`
(QSV, its ICQ mode). These three starting values are **not tuned**: nobody has run them on hardware.
VideoToolbox gets `-q:v 60` (`106 - 2*CRF`, its scale runs the other way), the value at which its
VMAF matched libx264 CRF 23 on the two fixtures at a larger file (see docs/hardware-encoders.md). Every encoder also gets the rung's `maxrate`
and `bufsize`, the same forced keyframe expression (`expr:gte(t,n_forced*2)`), `-g` equal to the
GOP, and its own flags against extra keyframes (`-no-scenecut 1 -strict_gop 1` for NVENC,
`-idr_interval 0` for VAAPI, `-adaptive_i 0 -adaptive_b 0 -idr_interval 0` for QSV; VideoToolbox has
no scene-cut keyframes to turn off). The measured VideoToolbox output has identical keyframe times
on every rung.

**Startup test.** `Tools.ProbeEncoder` encodes ten blank frames to the null muxer. The shipped
FFmpeg has no `lavfi`, so the frames come from the `rawvideo` demuxer reading `/dev/zero`, which the
build already has. The worker keeps running when the test fails: it logs one warning with the
encoder's name, counts `cipherframe_encoder_fallbacks_total{encoder,stage="startup"}`, and uses
software for every job. FFmpeg's message is dropped because it can name the device.

**Per-job retry is per transcode, not per rendition.** One FFmpeg process encodes every rendition
through a split filter, so a failure cannot be attributed to one rendition, and a retry of just one
would need a second decode of the source. When a hardware transcode fails (not on a timeout or a
cancel), the worker clears the output and runs the whole transcode once more with libx264, counts
`..{stage="job"}`, and logs `hardware encode failed; retrying with software` with the encoder name.
A source that is genuinely bad fails both runs and the asset fails as before.

**Recorded on the job.** The log line above, and the signed manifest: `encoder.video_codec` is the
encoder that made the output (`libx264`, `h264_nvenc`, ...) and `encoder.preset` is set only for
libx264, so a manifest never claims a preset a hardware encoder did not use. The masked variant's
re-signed manifest keeps the original's record.

**Metrics.** `encoder` is added to `cipherframe_transcode_duration_seconds` (five fixed values, two
outcomes, so ten series per bucket); existing dashboard queries aggregate it away. The fallback
counter has the labels `encoder` and `stage` (`startup` or `job`).

**Image.** A fully static glibc FFmpeg cannot use any of these encoders: libva and the NVIDIA
runtime load their drivers with `dlopen`. The static distroless `worker` image is therefore
unchanged and a second target, `worker-hw` (`docker build --target worker-hw`), carries a dynamically
linked FFmpeg with `h264_nvenc` (`nv-codec-headers` n12.2.72.0, pinned by checksum; needs NVIDIA
driver 550.54 or newer), `h264_vaapi` (`libva`) and `h264_qsv` (`libvpl`), plus the `hwupload`
filter, on Debian bookworm from the same dated snapshot with the runtime libraries and the Intel and
Mesa VAAPI drivers. The build fails if the binary needs any shared library beyond glibc, libva and
libvpl. x264 and dav1d stay static, `--disable-everything` stays, and `--enable-nonfree` is absent.
`libva` and `libvpl` come from the Debian packages of the snapshot (MIT) rather than from source
builds. The image's `SOURCE.md` has its own template. This departs from ADR 0063's wording
("the Linux worker image adds"): a second image keeps the hardened default image as it is, at the
cost of releasing two worker variants if the owner wants the second published.

**VideoToolbox runs native only.** As ADR 0063 says, with `CIPHERFRAME_FFMPEG_PATH` pointing at an
operator-supplied FFmpeg. That FFmpeg is outside the project's licence review, and the measured one
here is a `--enable-nonfree` build kept for measurement only; nothing of it is shipped.

## Consequences

- Hardware is opt-in per worker and failure costs a repeated transcode, never a failed upload.
- Retrying the whole ladder is wasteful when the failure is in one rung only; revisit if a rung
  fails in practice and the cost shows up.
- NVENC, VAAPI and QSV arguments, quality values and caps behaviour are untested on hardware and are
  marked so in the documentation. VAAPI's QVBR and QSV's ICQ may need other settings on some
  drivers; a failing driver falls back to software.
- Two worker images means two things to scan and release; the release workflow still builds one.
- M10-3 adds codecs by extending `videoArgs`, `FFmpegName` and the image's `--enable-encoder` list.
