# 0046. Thumbnails: poster, sprite sheet, thumbnail track

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (M7-2)
- Deciders: implementer; the owner reviews the choices below

## Context

M7-2 asks for a poster, a sprite sheet with a WebVTT thumbnail track and an I-frame playlist for every
asset. The brief fixed three things: faces are personal data, so the masked variant's images must come
from the masked output and a masked session must only ever see masked images; media segments are
AES-128 encrypted as whole segments, so an I-frame playlist has to be valid for players that cannot
decrypt a byte range; and nothing is publicly addressable, so images go through a playback session on
the edge, never through a presigned URL. Everything below is a judgement call the brief left open.

## Decisions

**No I-frame playlist is shipped.**

- An I-frame playlist (`EXT-X-I-FRAMES-ONLY`) lists single I-frames, each a byte range of a media
  segment (`EXT-X-BYTERANGE`). Segments here are encrypted as one AES-128-CBC unit under their own IV
  (ADR 0024, docs/encryption.md), so the bytes of one frame cannot be decrypted without the whole
  segment before them, and RFC 8216 gives no way to say "decrypt the segment, then take this range".
  A playlist that points into ciphertext would be one players cannot play.
- Whole-segment entries are not a valid I-frame playlist either: an entry must be one I-frame, and
  players use the list to show single frames. It would be a second, coarser copy of the media playlist.
- So the master playlist has **no** `EXT-X-I-FRAME-STREAM-INF`, and there is no I-frame artifact kind.
  Scrubbing previews come from the sprite sheet and the thumbnail track. Revisit when a player needs
  trick-play I-frames: the options are separate I-frame-only renditions with one I-frame per encrypted
  segment, or CMAF `cbcs` encryption, which allows a range of a segment to be decrypted.

**One pass: the thumbnails come out of the ladder's FFmpeg run.**

- The transcode already decodes the source once and splits it into one branch per rendition
  (ADR 0024). Two more branches of the same split feed the poster and the sprite sheet, so there is no
  second decode and no second process. Both are extra outputs of that one run (`mjpeg` into the `image2`
  muxer), so the transcode timeout bounds them and they report no progress of their own.
- The images are plaintext derived from plaintext, so they follow pipeline.go's rule: they are written
  to the job's private directory (mode 0700), read into memory for the upload and removed with the
  directory. The masked variant's run is the asset.mask job's own transcode of the masked file, so its
  images are made from the masked file and from nothing else.
- The shipped FFmpeg build gains the `mjpeg` encoder, the `image2` muxer and the `trim`, `setpts` and
  `tile` filters, and the worker's startup check requires them. A worker image built before this change
  refuses to start with a message that names what is missing.
- Thumbnails are an addition to the asset, not the asset: if the images are missing or are not the
  size the plan asked for, the variant is published without them and the cause is logged. Failing a
  good encode over a poster would be worse than a missing poster.

**What is generated.**

- Poster: one JPEG at 10 percent of the duration, at most 640 pixels wide, never upscaled, with the
  display aspect ratio (rotation and sample aspect ratio are applied by the same path as the ladder).
  It does **not** avoid black frames: detecting them would need a second pass or a filter that is not in
  the minimal build, which the brief only asked for "if cheap".
- Sprite sheet: one JPEG grid of tiles, each fitting 160 x 288 pixels (a portrait video keeps its
  shape), at most 10 columns, one tile every 10 seconds. A longer video uses a longer interval so
  there are at most 600 tiles (a 3 hour video: every 18 seconds), which keeps the sheet far below the
  JPEG size limit. The last tile covers the end of the video; the grid is padded to a full row.
- Thumbnail track: WebVTT, one cue per interval, payload `sprite.jpg#xywh=x,y,w,h`. It is written by
  Go from the plan, never by FFmpeg, and the sprite size read back from the file must equal the plan.
- Existing assets are **not** backfilled: they have no thumbnails and the routes answer `404` for them
  until they are processed again.

**Storage, registry and deletion.**

- The objects sit directly under each variant's HLS prefix: `hls/poster.jpg`, `hls/sprite.jpg`,
  `hls/thumbnails.vtt` and `masked/hls/...`. A masked image can never share a key with an original,
  the prefix scan that clears a variant before a retry clears its thumbnails, and the purge reaches
  them without a new prefix (`keys.VariantPoster`, `VariantSprite`, `VariantThumbnails`). The old
  asset-level `poster.jpg` key (never written) is gone.
- They are registered in `asset_artifacts` per variant as kinds `poster`, `sprite` and `thumbnails`
  (migration 00027 widens the kind check; no new table), `DeleteAssetHLSArtifacts` now removes them with
  the rest of a variant, the purge registry holds all three as per-variant kinds (the "not written yet"
  poster entry is now real) and the classifier maps each to its kind and variant, so the signed deletion
  record counts them separately for each variant.

**Manifest.**

- Each variant gets an optional `thumbnails` list of `kind` (`poster`, `sprite`, `thumbnails`), `path`
  (relative to the variant's HLS prefix, like every other path), `sha256` and `size`: at the top level
  for the original variant and inside `masked` for the masked one. The signature covers every hash.
- Like subtitle tracks (ADR 0044) they are in no Merkle tree, so `top_level.root`, every proof and every
  timestamp of the media are unchanged, and a thumbnail has no proof. With none the member is absent,
  so a manifest without thumbnails is byte for byte what it was and the schema stays
  `cipherframe.manifest/v1`. All three are listed together or not at all.
- They are part of the first signing (original) and of the re-signing that publishes the masked variant,
  both of which already exist; no other signing path changes. Re-signing for a subtitle change carries
  the lists over untouched.
- Verification: `POST /v1/verify` with `asset_id`, `variant` and the path (`poster.jpg`, ...) answers
  `ours` or `modified` with no proof, and the original's poster does not verify as the masked
  variant's. The offline verifier lists them in `Paths` for their variant (they sit in the HLS tree, so
  a downloaded tree holds them). A hash-only lookup does not search them, as for tracks.

**Serving.**

- Three routes, all on the edge, all behind the guard of the media playlists (a `manifest`-scope token,
  the session row, `token_in_url`, CORS, the one generic `401`): `GET /v1/play/{session_id}/poster.jpg`,
  `.../sprite.jpg` and `.../thumbnails.vtt`. The object key is built from the tenant, asset **and
  variant** of the verified token, never from the request, so a masked session cannot name an original
  image. A masked variant with no images answers `404`; there is no fallback to the original's.
- They are always streamed by the edge, even for tenants with `delivery = presigned` (ADR 0032): no
  code path presigns them, and a test asserts the response is served directly with a body and no
  storage URL. They are unencrypted images of faces; a presigned URL would outlive the session check.
  Responses are `no-store`, `Referrer-Policy: no-referrer`, `image/jpeg` or `text/vtt`. A fetch is not a
  row in the access trail.
- The thumbnail track names the sprite by the relative `sprite.jpg`, which resolves to the session's
  own sprite route. With `token_in_url` on, the edge adds `?t=<token>` to each reference on the way out
  (the stored file never holds a token, as with playlists).
- **How a player finds them.** HLS has no tag for a poster or a thumbnail track, and the master
  playlist is the one place a player cannot be told more without breaking strict parsers, so the names
  are fixed and sit beside the master: replace `master.m3u8` in `manifest_url` with `poster.jpg` or
  `thumbnails.vtt` (`sprite.jpg` is reached from the track). A `404` means the asset has none. The
  session creation response is unchanged. Revisit if integrators want the URLs in the response
  (`poster_url`, `thumbnails_url`).

## Consequences

- A video costs two small extra outputs in the transcode it already runs; the sprite sheet is a few
  hundred kilobytes for a feature-length video.
- Faces appear in the poster and the sprite sheet, so they are personal data (docs/privacy.md); the
  masked variant's are masked because they are made from the masked file, and the deletion record counts
  every one. Images are not encrypted: like subtitles, the session is their only access control, and
  anyone with a valid session can keep them.
- No trick-play I-frame playlist, no black-frame avoidance, no backfill of earlier assets, no custom
  poster upload and no per-tenant sizes or intervals. A worker image without `mjpeg`, `image2`, `trim`,
  `setpts` or `tile` no longer starts.
