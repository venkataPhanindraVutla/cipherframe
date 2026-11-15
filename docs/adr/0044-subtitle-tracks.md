# 0044. Subtitle tracks

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (details under P12, [ADR 0043](0043-subtitle-and-watermark-parameters.md))
- Deciders: implementer; the owner reviews the choices below

## Context

ADR 0043 decided what subtitles are: WebVTT, or SRT converted to WebVTT on upload; up to 20 tracks per
asset, each at most 2 MB, with a BCP 47 language tag, a label and a default flag; the transcript import
endpoint; tracks hashed into the manifest, served only through a playback session and registered with
the purge (I6). M7-1 had to turn that into endpoints, storage, a manifest change and playlist serving.
The choices below were not covered by ADR 0043, 0033, 0036 or 0042. Each takes the conservative option.

## Decisions

**Where tracks sit in the manifest.**

- Tracks are **not** in the top-level Merkle tree. The top-level `root` (also the `top_root` column and
  what every inclusion proof and RFC 3161 token refers to) stays the identity of the encoded media. A
  track can be added or deleted at any time after the asset is ready; putting it in the tree would change
  the root, and so invalidate every proof issued before, each time. Tracks are also shared by the
  original and the masked variant (the words do not depend on the picture), which has no single tree to
  join.
- Instead the manifest gets one optional member, `subtitles`: a list, in track ID order, of `id`,
  `language`, `default`, `origin` (`upload` or `import`), `path` (`subtitles/<id>.vtt`, relative to the
  asset, not to a variant's HLS prefix), `sha256` and `size`. The DSSE signature covers every hash. With
  no tracks the member is absent, so the canonical bytes of a manifest without tracks are exactly what
  they were before, and the schema stays `cipherframe.manifest/v1`: a verifier that does not know the
  member ignores it and still checks the signature and the media.
- The **label is not recorded** in the manifest. It is a free-text title a tenant types, and the manifest
  holds none (ADR 0040: no member that could hold a file name or title; a test enforces it). Language,
  default flag and origin are enumerable and stay.
- Adding or deleting a track builds the manifest again from the stored one with the new list, signs it
  with the current key and replaces the row in the same transaction (the way masking does), which also
  queues the RFC 3161 job when anchoring is on. The earlier timestamp token goes with the old row.
- Concurrency: every change takes the asset row lock. The masking job reads the manifest, signs and
  commits later, so it now commits only if the stored manifest still has the payload it started from
  (`ReplaceManifest`, `db.ErrManifestChanged`) and otherwise reads and signs again (up to five times), so
  a track added meanwhile is never rolled back.

**Verification.**

- The offline verifier checks a track by its manifest path (`subtitles/<id>.vtt`) for either variant.
  `Paths` stays the HLS files of a variant, and a new `SubtitlePaths` lists the tracks: a download of one
  variant's HLS tree does not hold tracks, so a track missing from it must not read as a missing file.
  `cipherframe verify DIR` checks a track found under `DIR/subtitles/` and never reports one missing.
- `POST /v1/verify` with `asset_id` and a track path answers `ours` or `modified` with no `proof` (no
  tree). `GET .../proof` for a track is `artifact_not_found`, and a hash-only verify does not search
  tracks.

**Access: tracks are not encrypted.**

- A track is stored as plain WebVTT. Encrypting it with the content key would need a key fetch per
  track, and no player decrypts WebVTT with AES-128. Access control is the session alone, the same as
  for the media playlists, and the ciphertext protection that segments have does not apply: anyone who
  can fetch a track through a valid session can keep it, and a revoked session loses the playlist and the
  track at once (both check the session row). Subtitles are words the tenant chose to ship with the
  video, so this is a smaller exposure than the video; a tenant whose subtitles are secret should not
  upload them.
- The routes are `GET /v1/play/{session_id}/subtitles/{subtitle_id}/media.m3u8` and `.../track.vtt`.
  Both require a token with the `manifest` scope and run the guard the media playlists run (session row,
  `token_in_url`, CORS, one generic `401`). The track is looked up by the tenant and asset in the token
  and the track ID in the path together, so a session cannot read another asset's or tenant's track; the
  object key is built from IDs. Responses are `no-store` with `Referrer-Policy: no-referrer`; the file is
  `text/vtt`. A track fetch is not a row in the access trail (the master fetch is).
- The master playlist gets one `EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs"` entry per track (`NAME`,
  `LANGUAGE`, `DEFAULT`, `AUTOSELECT=YES`, `FORCED=NO`, `URI`) and `SUBTITLES="subs"` on every variant.
  Each track's media playlist has one WebVTT segment as long as the asset (the duration is copied into
  the track row when it is added). A session that already fetched the master keeps the list it saw.
- A label and a language are tenant text written into quoted attributes, and HLS has no escape. Labels
  lose control characters, line breaks and bidirectional overrides when they are stored, and are written
  with `"` as `'`; a language that is not a language tag is written as `und`; two tracks with one label
  get ` (2)` and so on, because `NAME` must be unique in a group. Nothing else of a tenant is ever
  written into a playlist.

**What is accepted, and what is rewritten.**

- The file is read as UTF-8 (a leading byte order mark is removed; NUL and invalid UTF-8 are refused;
  CRLF and CR are read as LF) and the stored file is written from the parsed cues, never copied: a bare
  `WEBVTT` header, then each cue as `HH:MM:SS.mmm --> HH:MM:SS.mmm` and its text. Header text, `NOTE`,
  `STYLE` and `REGION` blocks, cue identifiers and cue settings (so no positioning or alignment) are
  dropped. SRT is told from WebVTT by the first line.
- Times: hours at most two digits, minutes and seconds below 60, three digits of milliseconds, no sign.
  Each cue must end after it starts, no cue may start before the one before it, and no cue may end more
  than **2 seconds** after the asset's duration. **Cues may overlap**: two speakers at once is ordinary,
  so "monotonic" means start times never go backwards.
- Cue text: at most 1000 characters (counted before sanitizing) and 12 lines, a track at most 20000
  cues, the file and the stored WebVTT each at most 2 MB. Plain text and the tags `b`, `i`, `u`, `v`,
  `lang` and `c` are kept (the class on `c` only from letters, digits and `_`; `v` needs a name, `lang` a
  language tag); every other tag is dropped and its text kept; `&`, `<` and `>` that are not part of
  `&amp; &lt; &gt; &nbsp; &lrm; &rlm;` or a kept tag are written as references; unmatched closing tags
  are dropped and open ones closed; control characters and bidirectional overrides are dropped. A cue
  with no visible text is refused, so a file is not accepted with a blank cue.
- Language tags are checked for the common well-formed shape (a 2 or 3 letter language, an optional
  script and region, variants) and stored in canonical case (`pt-br` becomes `pt-BR`); extension and
  private-use subtags are refused. A label is 1 to 100 characters.
- The uploaded file name is read by nothing (the multipart `filename` is never looked at), appears in no
  key, row, log or response. A field error names the field and the cue number, never the content.

**Behaviour.**

- Upload and import are validated, stored and signed inside the request, not by a job: the work is
  bounded by 2 MB, and the answer then says whether the track exists. The two routes accept up to 4 MB
  of request body (multipart framing, or JSON) where the rest of the control plane accepts 64 KB.
- The object is written to the bucket while the asset row is locked and after the asset was checked, so
  a deletion that starts meanwhile either sees the track in storage or is refused it; a failure after the
  write removes the object. Deleting removes the object first, in the transaction, so a failure leaves
  the track as it was and repeating the call finishes it.
- A track is the **default** when the request says so; a new default replaces the earlier one, and
  deleting the default track does not promote another. Two tracks may share a language and a label.
- Only a `ready` asset takes or loses tracks: `409 asset_not_ready` for one that is not ready, `409
  conflict` for one that is being deleted (its tracks stay until the purge), `404` for a deleted one
  and for another tenant's. The 21st track is `409 conflict`. Listing and reading work for any asset
  that is not deleted.
- Transcript import takes `start` and `end` as seconds (decimal numbers, rounded to the millisecond),
  `text` as plain text that is never read as markup, and an optional `speaker` that becomes a `v` tag.
  The track's origin is `import`.
- Scopes follow the neighbours: `assets:write` adds, imports and deletes, `assets:read` lists and reads.
  Adds and deletes are audited as `asset.subtitle.add` and `asset.subtitle.delete`, with the asset as the
  target and no content.

**Storage and deletion.**

- A track is `t/<tenant>/a/<asset>/subtitles/<sub_...>.vtt` in the delivery bucket (`keys.Subtitle`), under
  the asset's prefix, so the purge enumerates it with everything else. It is registered in
  `asset_artifacts` as kind `subtitle`, the purge classifier gives it kind `subtitle` with no variant (it
  belongs to neither), and the signed deletion record counts it. Its metadata is in the new table
  `asset_subtitles` (migration 00023), which the purge transaction empties. A track ID is a typed ID,
  prefix `sub`.

## Consequences

- Adding a track costs one signature and one manifest row, never a change to the media trees, proofs or
  timestamps of the media. Each add or delete does produce a new manifest payload, so an RFC 3161 token
  stamps the manifest as of its last change.
- The label can be changed by nobody and proven by nobody: it is not signed. A track's words are signed
  by hash, so changing the words is detectable and renaming the track is not.
- Tracks leave no ciphertext protection and are unrelated to the content keys, so crypto-shredding does
  not apply to them: only deleting the objects removes them.
- Not covered: forced subtitles, styled formats (TTML, SCC), cue positioning, per-track access control, a
  way to edit a track in place (delete and add), tracks for an asset that is not ready, and pushing a
  changed list to a session that already has the master playlist. The thumbnail track of M7-2 is a
  separate artifact.
- Revisit if a tenant needs secret subtitles (per-track encryption) or if the 4 MB request cap, the 2 MB
  track cap or the synchronous path proves too small or slow.
