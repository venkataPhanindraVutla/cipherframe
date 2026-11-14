# 0038. Encoder preset and detection stride settings

- Status: Accepted
- Date: 2026-11-14
- Gate: none
- Deciders: project owner
- Amends: [0024](0024-encoding-defaults-and-ffmpeg-build.md) (the libx264 preset is configurable), [0036](0036-face-masked-variant.md) (the masker may detect on a stride)

## Context

ADR 0037 ran `asset.mask` beside `asset.process`. Measured on a 42 s, 1260-frame 720p recording on an
8-CPU Docker host, the blurred variant went from 85 s to 62 s to ready. The two remaining costs are
the masker (face detection on every frame) and the libx264 encodes at the `medium` preset (ADR 0024),
in both the original and the masked ladder. These settings target about 30 to 40 s on the same
recording.

## Decision

1. **`CIPHERFRAME_WORKER_X264_PRESET`** (worker, optional). One of the libx264 presets `ultrafast`,
   `superfast`, `veryfast`, `faster`, `fast`, `medium`, `slow`, `slower`, `veryslow`. Default
   `medium`, which is the behaviour of ADR 0024. Anything else is rejected at config load, with an
   error that names the variable. Both variants use it, and the manifest records the preset in use.
   `media.TranscodeSpec` carries it (empty means `medium`). The keyframe-alignment arguments
   (`-g`, `-keyint_min`, `-sc_threshold`, `open-gop=0`, `-forced-idr`, `-force_key_frames`) are not
   touched, so renditions stay switchable at any preset.
2. **`CIPHERFRAME_ML_DETECT_EVERY`** (masker, optional). A whole number of at least 1, default 1 (the
   detector runs on every frame, as in ADR 0036). With N greater than 1 the detector runs on frames
   0, N, 2N and so on. On the frames in between the most recent detection result is reused as if it
   had just been detected, and goes through the same padding and hold logic, so a face stays blurred
   on skipped frames. Any other value stops the masker at startup with a message naming the variable.
   There is no `_FILE` variant: it is not a secret.
3. **`faces_detected`** now means: frames on which at least one face box was applied from a
   detection, including a reused one. Boxes kept only by the 1 s hold after detections stop are still
   not counted. At N = 1 the value is unchanged.

## Consequences

- `veryfast` gives lower quality per bit than `medium`. The `-maxrate` and `-bufsize` caps of ADR 0024
  still bound every rendition, so the file size does not grow; the picture is a little softer at the
  same rate.
- With N = 2 a fast-moving face can lag its box by one frame. The 25 % padding per side and the hold
  absorb that. Larger N widens the lag; N above 3 or so is not recommended for fast motion.
- `faces_detected` at N greater than 1 counts reused detections, so it can exceed the number of
  frames on which the detector itself found a face. It still means "frames that were blurred because
  of a detection".
- Defaults are unchanged: a deployment that sets neither variable behaves as before.
