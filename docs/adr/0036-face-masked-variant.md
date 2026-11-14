# 0036. Face-masked variant of an asset

- Status: Accepted (worker placement flagged for owner review)
- Date: 2026-11-14
- Gate: P20 (face detection model only), P21 (worker, face masking only)
- Deciders: project owner
- Amended by: [0037](0037-faster-face-masking.md) (`asset.mask` is enqueued at commit and runs beside `asset.process`)

## Context

Some deployments must let a viewer watch a recording without seeing the faces in it, while other
viewers of the same asset still see the original. Cipherframe already decides per session which
bytes a viewer may fetch, so it is the natural place to hold both versions and to enforce which one a
session gets.

Face detection needs an ML model. The worker is Go plus a minimal FFmpeg build (ADR 0024). The v2.1
plan already has a Python ML worker that consumes jobs through the hand-off table (ADR 0010). This
pulls that worker forward for one task kind.

Existing rules that constrain the design:

- Envelopes never carry secrets, signed URLs or source object keys (ADR 0010).
- Plaintext video touches the worker's local disk, never storage (ADR 0027).
- Each asset has exactly one content key today (`content_keys` is unique on `asset_id`).

## Options considered

Where detection runs:

1. **Python worker on the hand-off table**: OpenCV detects faces and blurs every frame. It uses the
   contract we already have and keeps the Go binary static.
2. **Go worker with ONNX Runtime through cgo**: one language, but the binary is no longer static, the
   minimal worker image grows, and blurring a region that changes every frame is awkward in FFmpeg.

Model:

1. **YuNet** (OpenCV Zoo, MIT): small, fast on CPU, and loaded by OpenCV's `FaceDetectorYN` with no
   extra runtime.
2. **MediaPipe BlazeFace** (Apache-2.0): also fast, but brings the MediaPipe runtime.

Default variant for a new session: masked unless asked otherwise, or always explicit.

Policy when detection is unsure: blur with hold and padding and publish even if no face was found,
or fail closed.

## Decision

- **Opt-in per asset.** `POST /v1/assets` takes `mask_faces` (boolean, default `false`). Only assets
  created with it get a masked variant.
- **Two variants.** An asset with masking has an `original` variant and a `masked` variant. Each has
  its own HLS tree under the asset's delivery prefix and **its own content key**, so a key from one
  variant never decrypts the other. `content_keys` becomes unique on `(asset_id, variant)`.
- **Pipeline.** `asset.process` is unchanged and makes the asset `ready` with its original variant.
  For a masking asset it then enqueues `asset.mask` on the `media` queue. That job:
  1. downloads the source into its private job directory (ADR 0027);
  2. writes an `external_tasks` row of kind `media.mask_faces` whose payload names the input and
     output files by path relative to the job directory (no object keys, no URLs);
  3. waits for the result, then transcodes the blurred file through the normal ladder into the
     `masked` variant, encrypts it under the masked content key, and adds it to the asset's signed
     manifest (ADR 0033).

  The asset carries `masking.state` (`pending`, `ready`, `failed`) and `masking.faces_detected`.
- **Masker.** A Python worker (`ml/`) claims `media.mask_faces` tasks from the hand-off table with
  its own database role. It **runs next to the Go worker and shares its work directory** (a sidecar
  container, or the same host), because the plaintext input and output may only live on that local
  disk. It reads frames, detects faces with YuNet (the model file pinned by SHA-256), blurs them, and
  pipes the frames to the worker image's FFmpeg with the source audio copied. The output is an
  intermediate file in the job directory, never uploaded.
- **Blur policy.** Blur **every** detected face. Detection runs on a copy downscaled to 640 pixels
  wide with a score threshold of 0.6 (recall over precision). Each box is padded by 25 % on every
  side, and the last box is held for one second after a face drops out of detection. The region is
  pixelated and then Gaussian-blurred so it cannot be sharpened back. If no face is found anywhere,
  the masked variant is still published with `faces_detected: 0`, so the embedding application can
  warn.
- **Sessions.** A session is bound to one variant at creation and recorded on the session. Edge
  serves playlists, segments and the key only for that variant. For a masking asset the default is
  `masked`, and `variant: "original"` must be asked for explicitly. If the masked variant is not
  `ready`, session creation for it fails with 409. It never falls back to the original. For an asset
  without masking, only `original` exists and `variant: "masked"` is a 409.
- **Model.** YuNet from OpenCV Zoo (`face_detection_yunet`, MIT). The exact file and its hash are
  recorded with the masker. The licence goes into NOTICE when the model ships in an image.

## Consequences

- Viewers can be given faceless playback without a second asset, and the decision of who sees the
  original stays with the embedding application, the same way as for every other session.
- The Python worker becomes part of v1, not v2.1, for this one task kind. Its database role is
  limited to `external_tasks`.
- Masking costs a full decode, detection pass and re-encode, plus a second ladder transcode. On CPU
  this is slower than the original pipeline. That is why it is opt-in and runs after the asset is
  already `ready`.
- Placing the masker beside the Go worker is the price of keeping plaintext off storage. A
  deployment that wants them on separate machines would need a different hand-off for plaintext,
  which is a new decision.
- Detection can miss faces: profiles, small faces or heavy occlusion. Padding and the hold reduce
  misses but do not remove them. This is a privacy aid, not a guarantee, and the documentation says
  so.
- Not covered: voice disguise, blurring named regions (ID cards, name tiles), or choosing which faces
  to keep. Each would be a new decision.
- The shipped FFmpeg gains the `rawvideo` demuxer and decoder (amending ADR 0024's list) so the
  masker can pipe frames in. FFmpeg never probes input as raw video, so an uploaded file is not
  read through it; it is used only when `-f rawvideo` is given.
- Deletion (M6) must purge both variants and destroy both content keys.
