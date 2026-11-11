# 0027. Segment encryption in the worker

- Status: Accepted
- Date: 2026-11-11
- Gate: none (M3-6 to M3-8; corrects one statement in ADR 0024)
- Deciders: implementer, under the owner's standing approval for M3 (flagged for owner review)

## Context

ADR 0024 says plaintext segments "never touch disk or storage". FFmpeg's HLS muxer cannot apply
AES-128 to fMP4, so it must write plaintext segments somewhere before Cipherframe encrypts them.
Implementing M3 also settled how segments are encrypted and what the stored playlists contain.

## Decision

- **Plaintext segments touch the worker's local disk, never storage.** FFmpeg writes them into a
  private per-job directory under `CIPHERFRAME_WORK_DIR` (base directory mode 0700). The pipeline
  reads each segment, encrypts it, uploads the ciphertext and deletes the plaintext file at once; the
  job directory is removed when the job ends, on success or failure. At startup the worker removes
  `job-*` directories older than the transcode timeout plus one hour (left by a killed worker). The
  content key never touches disk or storage. This replaces ADR 0024's "never touch disk" wording.
- **Cipher**: AES-128-CBC with PKCS#7 padding (RFC 8216 `METHOD=AES-128`) under the asset's content
  key, with a **random explicit 16-byte IV per segment** recorded in the playlist.
- **Init segments are not encrypted**: they hold only codec configuration. The playlist places
  `EXT-X-MAP` before the first `EXT-X-KEY`, so the key does not apply to it.
- **Stored playlists are canonical templates** rendered by Cipherframe (not FFmpeg's text). Their key
  URI is a fixed placeholder that edge rewrites per session (M4); stored playlists never contain
  tokens or real key URLs.
- The shipped FFmpeg also enables the `split` filter: one decode, one scaled branch per rendition, in
  a single process.

## Consequences

- Anyone with root on a worker node while a job runs can read that asset's plaintext segments. Run
  workers on dedicated nodes with encrypted local disks; this is documented in the threat model.
- Disk need per concurrent job is roughly two to three times the source size.
- A crash between FFmpeg finishing and the sweep leaves plaintext on that node's disk until the next
  worker start or the age threshold passes.
