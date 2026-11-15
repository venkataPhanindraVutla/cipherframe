# 0049. Per-tenant brand logo burned in at transcode

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (M7-4; the owner's parameters are in [ADR 0043](0043-subtitle-and-watermark-parameters.md))
- Deciders: implementer; the owner reviews the choices below

## Context

ADR 0043 fixed what a logo is: a PNG of at most 256 KB and 1024 pixels on the longer side, in one of
four corners, at a fixed share of the video width, blended at 10 to 100 percent opacity, burned in at
transcode (the logo is the same for every viewer, so invariant I3 allows it), recorded per asset and in
the signed manifest, and not retroactive. The brief left the rest open: where the setting lives, how the
untrusted PNG is handled, how FFmpeg gets it, how versions are kept and removed, and how the logo
fits the purge. Everything below is a judgement call within those parameters.

## Decisions

**Scope and API.**

- The logo is a tenant setting, like the playback and quota settings: `admin` scope, no client or asset
  scope. `PUT /v1/brand/logo` (multipart: `file`, optional `corner`, `opacity`, `enabled`) stores a new
  version and makes it current; `GET` returns the metadata (never the image); `PATCH` changes corner,
  opacity or the enabled flag without a new upload; `DELETE` removes the setting. Defaults are
  `bottom_right`, 100 percent, enabled. `enabled: false` keeps the image but gives new assets no logo.
- Every change is audited (`brand.logo.put`, `.update`, `.delete`) with the version ID and no file name.

**The upload is checked before anything touches FFmpeg.**

- Order: size (413 over 256 KB), PNG signature, the chunk list (an animated PNG is refused), the
  header's dimensions through `png.DecodeConfig` (so a few hundred bytes that claim a billion pixels are
  refused before any pixel memory is allocated), then a full decode with Go's `image/png`.
- Sides must be between 16 and 1024 pixels. The 16-pixel floor is a judgement call: a smaller image is
  not a logo and, scaled to 15 percent of a video's width, is a smear. A fully transparent image is
  refused (it would be a silent no-op).
- **Animated PNG is refused, not flattened** (`400`). Go would decode only the default image and drop the
  animation silently; a tenant who sent an animation should be told it will not play.
- The decoded pixels are written back with Go's `png.Encoder` (8-bit RGB, or RGBA when some pixel is
  not opaque; Go's encoder chooses) and **only that file is stored**. Text, EXIF, ICC, gamma, physical
  size and every other ancillary chunk are gone. The stored file must also fit 256 KB: a palette PNG
  that grows past it when expanded is refused with `413`.
- The uploaded file name is never read: the form handler ignores it, it reaches no key, no row, no log
  and no response. The stored hash is the hash of the re-encoded file.

**FFmpeg is given raw pixels, not a PNG.** This departs from the brief's suggested "PNG input with the
`png` decoder", for a security reason found while checking what that decoder needs. FFmpeg's PNG
decoder needs zlib, and the shipped build deliberately has none, so that compressed MP4 headers and
Matroska header compression of the *untrusted video* are rejected (worker.Dockerfile). Adding zlib for a
logo would reopen both. Instead the worker decodes the stored PNG with Go (again under the size
bounds), writes straight-alpha RGBA into the job's private directory (0600) and passes it as
`-f rawvideo -pixel_format rgba -video_size WxH -framerate 1 -i file:...` with `-protocol_whitelist file`
for that input. The `rawvideo` demuxer and decoder were already in the build for the face masker, so
**FFmpeg never parses anything the tenant sent**, not even the PNG Go produced. The build gains only the
`overlay` and `colorchannelmixer` filters; `CheckCapabilities` now also requires those two and the
`rawvideo` decoder and demuxer. Worker images built earlier refuse to start with a message that names
them: **worker images must be rebuilt** (the `tools` and worker targets of `build/worker.Dockerfile`).

**Where in the filter graph: per picture, after scaling.**

- The logo is drawn on each rendition after `scale` and `setsar=1`, from its own branch of a `split` of
  the logo stream, scaled to that rendition's width. Drawing it once before the split would blend it at
  source resolution and then scale it down with the picture: it would be softer on small rungs, would
  depend on the source's sample aspect ratio (setsar comes after) and could not honour "a fixed share of
  each rung's width" exactly. Per rung it is sharp and exact, and costs one small scale and overlay per
  branch.
- The split, the fps filter, the keyframe flags, the segmenter and every check (`CheckAligned`, rendition
  output checks) are untouched; the logo is a stage inside each branch, so all rungs still see the same
  frames at the same timestamps. The test suite asserts the alignment with a logo on.
- **Layout.** Width 15 percent of the picture's width (the constant `media.LogoWidthPercent`, recorded
  in the manifest), the logo's own aspect ratio, shrunk to at most 25 percent of the height (a very tall
  logo would otherwise run off a 16:9 picture), a margin of 2 percent of the width to the chosen corner,
  every size rounded to an even number so chroma lines up. A small logo is scaled up to its share:
  a 16-pixel logo on 1080p is blurry, which is the tenant's choice of file.
- **Opacity** multiplies the logo's alpha with `colorchannelmixer=aa=`; 100 percent adds no filter. The
  blend is done in 8-bit 4:2:0 (`overlay=format=yuv420`), which every output is anyway.
- Known limit: the logo is scaled as straight alpha, so a logo whose transparent pixels are black may
  show a faint dark edge when it is shrunk. Premultiplying would need two more filters in the build;
  revisit if a tenant sees it.
- **The masked variant** gets the same logo. The masker blurs faces in the file it writes, and the
  masked variant's transcode (the asset.mask job's own) reads that file and draws the logo on it, so
  the logo is applied after masking by construction: the blur can neither cover nor distort it.
- **Thumbnails** are cut from the same frames and show the logo: the poster and every sprite tile get
  it at that picture's own width (15 percent of 640 or of 160 pixels), so a scrubbing preview matches
  the video. For the masked variant they come from the masked output as before.
- Pre-existing bug fixed on the way: the poster branch used `setpts=PTS-STARTPS`, which real FFmpeg
  rejects (the constant is `STARTPTS`). The unit tests only compared strings, so the M7-2 thumbnails
  never ran against a real FFmpeg until the media tests here did. Fixed in `internal/media/thumbnails.go`.

**Versions are immutable and stored under the tenant.**

- A logo version is `t/<tenant>/branding/logo/<version>.png` in the delivery bucket
  (`keys.BrandLogo`, `keys.BrandLogoPrefix`), with a `tenant_logo_versions` row (hash, size, pixels). It
  sits outside `keys.AssetPrefixes`, so deleting an asset can never reach a logo. A new upload is a new
  version; the bytes are never replaced. A placement change keeps the version.
- `tenant_logos` holds the tenant's current version and placement; `asset_logo_pins` holds what each
  asset was made with.

**A retried job uses the version it started with.**

- The first job of an asset to start, `asset.process` or `asset.mask` (they run in parallel), reads the
  tenant's current logo and records it in `asset_logo_pins` (version ID, SHA-256, corner, opacity; all
  null when the tenant has no enabled logo), once (`ON CONFLICT DO NOTHING`). Every later job and every
  retry reads the row back. So both variants and all attempts of one asset use one version, and the
  masked variant is not affected by a change made after the original started.
- The row is written under the tenant's brand advisory lock in its own short transaction, before the
  download. The worker then checks the downloaded object against the pinned SHA-256, decodes it and
  never trusts the bucket's bytes beyond that.
- If the pinned object is missing or does not match, the job fails the asset for good
  (`logo_unavailable`) instead of publishing it without its logo: every asset of a branded tenant
  carries the brand.

**When old versions are deleted.** On every upload and every removal, in the same transaction and under
the same brand lock, Cipherframe deletes each version that is not current and is not needed by an asset
whose first job may still run: an asset pinned to it that is `committed` or `processing`, or whose
`masking_state` is `pending`. Objects go first, then rows; a failure leaves the rows and the next change
finds them again. Pinning takes the same lock, so a version cannot be removed between an asset reading
the current logo and recording it (tested with a four-connection pool, which would deadlock on a lock
taken the wrong way). A placement change removes nothing. There is no scheduled sweep: a version kept
for an in-flight asset is removed by the next upload or removal, so after a removal an old image may
stay until then. It is a tenant's own logo, not personal data, and nothing serves it.

**The purge and the deletion record (I6).** A logo is the tenant's configuration, not an artifact derived
from an asset, so it is not in `asset_artifacts`, not a purge registry kind and not in the signed
deletion record. Its effect on an asset is burned into that asset's segments and thumbnails, which are
registered and purged as usual. Pin rows hold only IDs, a hash and a placement (no content) and stay
with the asset's tombstone. There is no tenant deletion yet; when there is, it must remove
`keys.BrandLogoPrefix(tenant)` and the three tables.

**Manifest.** The encoder section gets an optional `logo` of `sha256` (of the stored PNG), `version`,
`corner`, `opacity_percent` and `width_percent` (15); the masked section gets the same member. Both
come from the pin, so they say what was drawn, not what the tenant has now. The logo is in no Merkle
tree, so the top-level root and every proof are unchanged. A manifest without a logo has no member and
is byte for byte what it was (the golden test holds). The schema stays `cipherframe.manifest/v1`; the
offline verifier decodes the manifest through the same struct and needed no change (a test opens one
with a logo). A verifier cannot check the logo's pixels in the video, only that the signed document
names the logo the tenant can still produce.

## Consequences

- **Not retroactive, and what that means.** There is no re-transcode in Cipherframe, so an asset keeps
  the logo it was made with, or none, for its whole life. Uploading a logo later does not brand the
  tenant's existing library, and **removing a logo does not remove it from videos already made**: the
  pixels are in the segments. A tenant that must change an old video's branding has to upload the source
  again as a new asset. A future re-transcode must delete the asset's pin row so it takes the logo of
  the day.
- A tenant's catalog can mix logos across assets; the manifest says which each asset has.
- The worker image changes (two filters), so every deployment must rebuild and roll the worker image
  before this version's worker starts; an old image fails the startup check by name.
- A hostile logo cannot reach FFmpeg: Go's decoder is the only code that parses it, under size and
  dimension bounds, and Go's PNG decoder is memory safe.
- Not covered: SVG, animation, a logo per client or per asset, a position other than four corners, a
  logo that scales with anything but the width, and retroactive application.
