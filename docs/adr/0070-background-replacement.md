# 0070. Background replacement for recorded people

- Status: Accepted
- Date: 2026-11-24
- Gate: none (owner decisions; the segmentation model is part of the P20 question for this feature only)
- Deciders: project owner

## Context

Interview and call recordings show the room behind the person. Organisations want to replace it the
way video-call tools do: blurred, or an image the organisation chooses, while the person stays
visible. Face masking (ADR 0036) already runs a frame-level pass in the masker next to the worker.

## Options considered

- **Copies:** apply the background to the existing variants; add a third `background` variant with its
  own key and ladder.
- **What goes behind the person:** an organisation image, falling back to blur; image only; an
  organisation setting choosing `none`, `blur` or `image`.
- **Raw recording:** never playable when the background is replaced; still playable on request when
  the source is kept.
- **Segmentation model:** MediaPipe Selfie Segmenter (Apache-2.0, built for webcam framing, fast on
  CPU); MODNet (Apache-2.0, cleaner edges, about 3 to 4 times slower); RobustVideoMatting (GPL-3.0).
- **Image configuration:** per tenant like the brand logo; per tenant with a per-upload override.

## Decision

- **Optional, per organisation.** A tenant setting `mode` of `none` (default), `blur` or `image`. The
  image is uploaded per tenant like the brand logo (ADR 0049): versioned, snapshotted on the asset at
  upload, never retroactive.
- **Per upload.** `replace_background` next to `mask_faces`; the two are independent. The background is
  replaced when `replace_background` is set and the snapshotted mode is not `none`; with `none` the
  upload is accepted and the background stays as recorded.
- **Copies.** No new variant.

  | Upload | `original` variant | `masked` variant |
  |---|---|---|
  | background and face masking | background replaced, faces visible | background replaced, faces blurred |
  | background only | background replaced, faces visible | none |
  | face masking only | as recorded (today) | faces blurred (today) |
  | neither | as recorded (today) | none |

- **The raw recording is never playable when the background is replaced.** Every rendition, the
  poster, the sprite and the thumbnails come from the replaced frames. The recording survives only as
  the source object, and only while the tenant keeps sources (`keep_source`, ADR 0069). If segmentation
  fails the asset fails; it never falls back to the recorded frames.
- **Model.** MediaPipe Selfie Segmenter, pinned by SHA-256 like YuNet, run by the masker in the same
  frame pass as face detection.

## Consequences

- An asset with the background replaced becomes `ready` only after the masker has run, so it is slower
  than one without.
- Segmentation is not perfect: hair and fast motion can show edges or brief flashes of the room. The
  original room is therefore reduced, not guaranteed hidden, and the documentation says so.
- Implementation details are recorded below when BG-1 merges.

## Implementation

(Added when BG-1 merges.)
