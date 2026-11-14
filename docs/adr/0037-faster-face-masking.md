# 0037. Faster face masking

- Status: Accepted
- Date: 2026-11-14
- Gate: none
- Deciders: project owner
- Amends: [0024](0024-encoding-defaults-and-ffmpeg-build.md) (the ladder may be restricted), [0036](0036-face-masked-variant.md) (when `asset.mask` is enqueued and where it runs)

## Context

ADR 0036 enqueues `asset.mask` when `asset.process` completes, on the same `media` queue. Everything
is therefore sequential. Measured on a 42 s, 1260-frame 720p browser recording on a laptop: the
original transcode takes 20 s and the original is ready at 22 s; then `asset.mask` starts, the masker
takes 41 s (about 6 cores) and the masked transcode 21 s, so the blurred variant is ready at 85 s.

Two things are wasted. The masker does not need the original variant, only the source, so it can
start as soon as the upload is committed. And the masked ladder repeats rungs a deployment may not
want, at an encoder preset that costs more than the intermediate file needs.

## Options considered

1. **Keep the sequence, tune only the encoders.** Smallest change, but the masker still waits for the
   whole original transcode.
2. **Enqueue `asset.mask` at commit, on its own queue, and make it wait for the original before it
   publishes.** The two jobs overlap. The only coupling is at the end, where the masked variant needs
   the original's manifest to re-sign.
3. **Let the masker write its own manifest.** Would remove the wait but splits the manifest in two,
   which ADR 0033 and the verifier do not allow.

Option 2, plus a configurable ladder and a faster intermediate encode.

## Decision

1. **Mask in parallel with the original.**
   - `asset.mask` is enqueued in the transaction that commits the upload and enqueues `asset.process`,
     only for an asset created with `mask_faces`. Completing `asset.process` no longer enqueues it.
     The job kind and arguments are unchanged; the argument type now lives in `internal/uploads`
     beside `ProcessArgs`, because the api role inserts it.
   - `asset.mask` runs on its own River queue, `mask`, worked `CIPHERFRAME_WORKER_MASK_CONCURRENCY`
     jobs at once (default 1, 1 to 64, like the media setting). `asset.process` stays on `media`, so
     the two never wait for each other's slots and cannot deadlock at any concurrency.
   - The job downloads and size-checks the source, runs the masker, transcodes the masked ladder (no
     progress reporting: the progress column belongs to the original), and then, before publishing
     anything, polls the asset every `MaskPoll` until it is `ready`. The wait is bounded by
     `CIPHERFRAME_WORKER_MASK_TIMEOUT` (the job's own limit grows by one more timeout to allow for it).
   - If the asset becomes `failed` or `deleted` (or the row is gone) while waiting, the job stops:
     it records `masking_state = failed` if the row still exists, removes the masked prefix and its
     artifact rows, and ends without retry. A timeout of the wait does the same.
   - **Source verification.** `asset.process` records the source digest (`RecordSource`) early, but
     the masking job can finish its own download before that. The job checks the stored size against
     the declared size at once, and compares the digest it computed with the one recorded on the asset
     once the asset is `ready`, before publishing. The guarantee of ADR 0036 (the masked variant comes
     from the bytes that were processed) is kept, and the masker is not held back by a value that only
     exists later. A mismatch fails masking without publishing.
   - `masking_state` is still reported `pending` for a `mask_faces` asset before it is ready: the API
     already treats an empty state as `pending`. `CompleteAssetProcessing` now keeps an existing
     `masking_state` instead of overwriting it with `pending`, so a masking failure recorded before
     the original finished is not lost.
   - The masked variant keeps its own content key. `CompleteMasking` still requires the asset to be
     `ready`; the re-signed manifest is built from the original manifest, which exists once the
     asset is ready.
2. **Configurable ladder.** `CIPHERFRAME_WORKER_LADDER_HEIGHTS` is an optional comma-separated subset
   of the ADR 0024 rung heights (1080, 720, 480, 360, 240), for example `720,360`. Unset means every
   rung. It is validated at startup (known heights only, no duplicates, not empty when set). Both
   variants use the same ladder. A selected rung taller than the source is skipped as before; if the
   source is shorter than every selected rung it gets one rendition at its own height, with the caps
   of the smallest selected rung.
3. **Faster masker intermediate.** The masker's intermediate libx264 encode moves from `veryfast` to
   `ultrafast` (crf 12, yuv420p unchanged). It is a local file that the ladder re-encodes afterwards.

## Consequences

- With the default concurrencies the masked variant is ready at about the larger of (original
  transcode) and (masker plus masked transcode), instead of their sum, on a machine with cores to
  spare. The original is not slowed in principle, but the masker and FFmpeg share cores, so on a small
  host both take longer than they would alone.
- Fewer rungs cut both transcodes roughly in proportion to the encoding work removed.
- A worker now needs the masker (or a mask timeout) for every `mask_faces` asset from commit on,
  not from ready on; an asset without a masker still becomes `ready` and plays as the original.
- Disk: the masking job and the processing job hold their job directories at the same time, so size
  `CIPHERFRAME_WORK_DIR` for `CIPHERFRAME_WORKER_MEDIA_CONCURRENCY + CIPHERFRAME_WORKER_MASK_CONCURRENCY` jobs.
- Jobs already queued by an older version on the `media` queue still run: the kind is registered
  whatever queue a row sits on.
- Not covered: sharing the decode between the original ladder and the masker, or running the masker
  on a GPU. Revisit if the masker, not the wait, becomes the bottleneck.
