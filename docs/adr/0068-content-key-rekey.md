# 0068. Content-key re-key

- Status: Accepted (flagged for owner review)
- Date: 2026-11-23
- Gate: none (M10-4; builds on [ADR 0020](0020-envelope-encryption-aead.md),
  [0027](0027-segment-encryption-in-the-worker.md), [0033](0033-integrity-design.md),
  [0042](0042-deletion-and-retention-details.md))
- Deciders: implementer

## Context

M10-4 asks for an audited, explicit operation that encrypts an asset's segments again under a new
content key, signs the manifest again and destroys the old key, while exactly one key stays active
per asset (I7). The brief left open: where the new objects live and what playback does around the
switch, how a crash is survived, how concurrent re-keys are refused, what counts as "every encrypted
artifact", the command shape and the audit trail. This records each choice.

## Decisions

**What is encrypted, so what is re-keyed.** Only media segments are encrypted (AES-128-CBC, an IV per
segment). Init segments, master playlists, thumbnails (poster, sprite, track) and subtitles are not
(ADR 0027, 0044, 0046). The media playlists hold the IVs, so they are rewritten with the segments.
A re-key therefore replaces the media segments and media playlists of every variant the asset has
(`original`, and `masked` when its manifest has one), and nothing else.

**One operation per asset, every variant.** The two variants have their own keys (ADR 0036) but are
re-keyed together, in one job and one switch transaction, so there is one answer to "which key
generation is this asset on". `assets.key_generation` (migration `00031`, default 0) counts
re-keys. A re-key is refused while the masked variant is still being made (`masking_state` not
`ready` or `failed`): that variant is published after the asset is ready, under a key created then,
and would be left on the old generation.

**Object layout: a generation directory, not in-place writes.** Generation 0 is where every asset
has always been. Generation n > 0 lives under `k<n>/` of the variant's HLS prefix
(`keys.VariantGenPrefix`): `k1/720p/seg-0.m4s`, `k1/720p/playlist.m3u8`. Overwriting in place cannot
be both crash-safe and atomic (a crash would leave some segments under each key), whereas new
objects at new keys leave the asset untouched until one database transaction flips it. The directory
sits inside the existing prefix, so deletion, the purge registry (`purge.Classify` strips the
generation) and the integrity paths (the manifest records `k1/720p/seg-0.m4s`, relative to the
variant prefix, so `verify` and the proof endpoints need no change) keep working. Init segments, the
master playlist and thumbnails are shared by every generation and stay where they are.

**Job: stage, then switch, then clean.** `asset.rekey` (default queue, 4 hours per run, 5 attempts):

1. Remove anything under `k<n+1>/` (an earlier attempt's staging; nothing there is referenced).
2. Read the signed manifest. For each rendition: read the stored playlist, then each segment in
   manifest order, **check its SHA-256 against the signed manifest**, decrypt with the old key and
   its IV, encrypt with the new key and a fresh IV, upload it to the new generation, and write the
   playlist with the new IVs. Plaintext exists only in memory, one segment at a time, and is cleared
   (the ADR 0027 rule). The new key is generated and wrapped in memory (`contentkey.Manager.Generate`)
   and only stored at the switch.
3. **Switch, in one transaction under the asset lock** (`LockAsset`): check the asset is still ready
   and at the generation the job started from; sign the manifest again (`signing.Prepare` first, so
   no second pool connection is taken inside the transaction) with the new segment and playlist
   hashes (`manifest.WithRekeyed`) and replace the stored one (its timestamp token goes with the
   old row); replace each variant's content key row (the old row is **deleted**, as in crypto
   shredding, and the new one takes its place); unregister the old objects and register the new
   ones; set `key_generation` to the next value; queue `manifest.anchor` when a TSA is configured
   (ADR 0041) and `asset.cdn_purge` when a CDN is configured (ADR 0065); write the audit event. The
   asset has one key per variant before and after.
4. After the commit, delete the old segments and playlists (found by listing, not from the registry).

A crash before the commit leaves the asset exactly as it was (playable under the old key; the
manifest, keys and registry are untouched) plus unreferenced staging objects, which the retry removes
before starting again. A crash after the commit is finished by the retry, which finds the asset past
`from_generation` (carried in the job arguments) and only deletes the old objects. Each attempt
starts from the beginning: no pending key is persisted, so there is no secret to protect between
attempts, at the price of redoing the reads and writes of a failed attempt.

**Playback around the switch: sessions are bound to a key generation.** A playback token carries the
generation of the asset when the session started (claim `g`, absent means 0; heartbeats keep it).
The edge reads the media playlists and segments of the token's generation, and the key route
refuses a session whose generation is not the asset's current one (`401`, like a revoked session).
So a session that started before the switch cannot get the new key and cannot decrypt new segments,
and one that started after cannot be served old objects. Old objects are deleted right after the
switch, with no grace period: a viewer mid-playback sees errors and starts a new session (a new
player load); the player's normal retry does this. The alternative (keeping old objects and the old
key for a while) would keep the old key alive, which is what a re-key is meant to end, so it was
refused. Sessions are not revoked: refusing the key is enough, and it leaves no access-trail noise.

**Concurrency.** `POST /v1/assets/{asset_id}/rekey` takes the asset lock, checks the state and looks
for an `asset.rekey` job of the asset that is waiting, running or due to retry (the same test the
deletion uses on River's table, run inside the transaction), and refuses with `409 conflict` if one
exists; otherwise it writes the audit event and the job in one transaction. A job that was
dead-lettered does not block a new request, so repeating the call is how a failed re-key is retried.
No new table. The purge waits for an active re-key like it waits for processing; a re-key whose
asset stopped being ready stops at its switch and removes what it staged.

**API and CLI.** `POST /v1/assets/{asset_id}/rekey`, scope `assets:write` (the same as deletion; no
new scope), no body, `202` with `{asset_id, job_id}`. Problems: `asset_not_ready` (any state before
ready or failed), `conflict` (deleting, masking in progress, re-key in flight), `not_found` (another
tenant, deleted). The CLI command is `cipherframe rekey ASSET_ID`, flat like `delete` and `status`
(ADR 0051), not `assets rekey`: the CLI has no `assets` group. It has no `--wait`: the asset
document does not show the generation, so completion is read from the audit log
(`asset.rekey_completed`). Adding `key_generation` to the asset document would allow a wait and is
left for the owner to ask for.

**Audit.** `asset.rekey_requested` (with the caller, in the request transaction),
`asset.rekey_completed` (in the switch transaction) and `asset.rekey_failed` (on the last failed
attempt, or at once for a failure no retry can fix). Events carry the asset ID only: no key, key ID
or object key, in events or logs. A stored segment that does not match the signed manifest, or does
not decrypt, is such a failure: the job is cancelled, the asset is left as it was and the event is
written. No metric was added; none of the existing ones fits.

## Consequences

- The default behaviour is unchanged when the operation is unused: generation 0 resolves to the
  existing keys, tokens without `g` mean 0, and no existing object moves.
- **What it does and does not do** (also in the threat model): it limits future use of a leaked
  content key. It does **not** help against plaintext or keys a viewer already saved, against
  ciphertext someone copied before the switch (with the old key, which they hold, it stays
  readable), or against ciphertext that outlives the deletion of the old objects: bucket versioning,
  bucket copies, and database backups (which hold the old wrapped key until they age out). Use it
  after a key may have leaked, and treat old backups and versions as exposed.
- Storage holds both generations until the old objects are deleted at the end of the job.
- A re-key reads and writes every segment once: it is I/O and memory (one segment) bound, and a
  failed attempt starts over.
- Editing the asset while it runs is safe: subtitle changes re-sign under the same lock and leave the
  renditions alone; if the renditions changed, the switch fails and the retry stages again.
- Revisit: resuming a failed attempt instead of restarting it, a generation in the asset document,
  and a grace period for viewers mid-playback.
