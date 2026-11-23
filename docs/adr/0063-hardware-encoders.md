# 0063. Hardware encoders

- Status: Accepted
- Date: 2026-11-23
- Gate: P17
- Deciders: project owner

## Context

M10-2 adds hardware-accelerated encoding with automatic software fallback. Keyframe alignment
across renditions (pitfall 4) must still hold, and quality and bitrate against software must be
measured and documented. ADR 0024 fixed libx264 in a minimal GPL FFmpeg 9.0.2 build, with the
option for operators to supply their own FFmpeg. The only hardware available to the project for
measurement is an Apple Silicon Mac; GitHub's standard CI runners have no GPU.

## Options considered

- **Targets:** NVENC (NVIDIA), VAAPI (Intel and AMD on Linux), QSV (Intel Quick Sync),
  VideoToolbox (macOS); any subset.
- **Test hardware:** this Mac only; this Mac and a cloud GPU instance on request; this Mac and a
  local Linux GPU machine.

## Decision

**All four targets, chosen per worker**

- `CIPHERFRAME_WORKER_ENCODER` selects `software` (the default, libx264), `nvenc`, `vaapi`, `qsv` or
  `videotoolbox`. Hardware is a property of the machine, so the setting belongs to the worker, not
  the tenant.
- Decoding, scaling and face masking stay in software; only the encode runs on the hardware. This
  avoids FFmpeg's non-free CUDA filters and keeps one filter graph for every encoder.
- Every encoder gets the same 2 s closed-GOP keyframe placement and per-rung `maxrate`/`bufsize`
  caps as libx264; quality targets use each encoder's constant-quality mode and are tuned on fixture
  media with VMAF.

**Automatic fallback**

- At startup the worker runs a short test encode with the selected hardware encoder. If it fails,
  the worker logs a warning without device details beyond the encoder name and uses software.
- If a hardware encode fails during a job, that rendition is retried once with libx264. Fallbacks are
  counted in a metric and recorded on the job.

**FFmpeg build and licensing**

- The Linux worker image adds NVENC (through the MIT-licensed `nv-codec-headers`), VAAPI (`libva`,
  MIT) and QSV (`libvpl`, MIT). No `--enable-nonfree` is needed, so the image stays redistributable
  under the existing GPL terms.
- VideoToolbox works only for a native worker on macOS, with an operator-supplied FFmpeg
  (`CIPHERFRAME_FFMPEG_PATH`); Docker on macOS has no access to it.

**Verification**

- VideoToolbox is measured on the project's Mac: size, VMAF and speed against libx264 on the
  fixtures, and the keyframe alignment tests.
- NVENC, VAAPI and QSV are built into the image and covered by tests of argument building, the
  startup probe and the fallback path. Their documentation marks them as **not verified on
  hardware** until someone runs the same measurement on a GPU; nothing is run on a paid cloud
  instance without the owner's go-ahead.

## Consequences

- Operators with GPUs get faster transcodes; operators without them see no change.
- Three of the four targets ship unmeasured. Their failure mode is a fallback to software, not a
  failed upload, but their quality and bitrate numbers are unknown until measured.
- The worker image grows by the three hardware libraries.
- ADR 0064 reuses these encoders for HEVC and AV1 where the hardware supports those codecs.
