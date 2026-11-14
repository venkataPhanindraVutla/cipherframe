# 0042. Deletion and retention details

- Status: Accepted (flagged for owner review)
- Date: 2026-11-14
- Gate: none (details under P11, [ADR 0040](0040-retention-and-privacy-defaults.md))
- Deciders: implementer; the owner reviews the choices below

## Context

ADR 0040 decided what is kept and for how long. M6 had to turn that into a purge job, a signed deletion
record, a time-to-live and a retention job. Several choices were not covered by ADR 0040, 0033 or 0036.
This records each, with the conservative option taken.

## Decisions

**Lifecycle.**

- A new state `deleting` sits between every live state and `deleted`. Playback (session creation and the
  key route), uploads, commit, processing and masking refuse an asset in it. `deleted` is the tombstone:
  the asset row stays, without its source object key or upload ID, and the audit rows stay.
- `DELETE /v1/assets/{asset_id}` answers `202` with the asset (`deleting`, or `deleted` for a tombstone).
  It is idempotent. Repeating it while the asset is `deleting` queues a new purge job only when no
  `asset.delete` job of the asset is waiting, running or scheduled (a job that was dead-lettered after
  its attempts), so repeating the call is how a stuck deletion is restarted.
- `GET /v1/assets/{asset_id}` returns the tombstone (`state: deleted`, `deletion.completed_at`) instead
  of `404`, so a client can see that a deletion finished. List endpoints leave deleted assets out.
  Commit, abort and `PATCH` of a deleted asset stay `404`.
- The deletion record of an asset that is not deleted (including `deleting`) is `404 not_deleted`, a new
  error code; another tenant's asset is `404 not_found`.

**Purge order and failure.**

- Content keys are destroyed only after storage has been listed empty, in the same transaction that
  stores the signed deletion record, drops the registry rows and the manifest and writes the tombstone.
  Destroying the keys first would shred sooner, but a retry could then no longer name them in the
  record. A failed purge therefore leaves the data encrypted and the keys where they were, and it never
  reports success: storage is listed up to four times, objects left after that fail the job, and a job
  out of attempts is dead-lettered with the asset still `deleting`.
- An in-flight `asset.process` or `asset.mask` job stops at its next check (before publishing, while
  waiting for the masker) and removes its own output; content keys are never created for a deleting
  asset. The purge waits (a snoozed retry every 15 seconds) while such a job is active, for up to two
  hours after the request, then purges anyway and relies on the job's own cleanup. Waiting avoids a job
  uploading behind the purge's final listing.
- Playback sessions of the asset are revoked (reason `asset_deleted`, one `revoked` row each in the
  access trail) when the purge starts. Session rows themselves stay.

**The deletion record** (`cipherframe.deletion/v1`).

- It counts objects and bytes per bucket, artifact kind and variant. An object that nothing in Cipherframe
  writes is counted as kind `other` rather than ignored. It names the destroyed content keys by ID and
  variant. `manifest_root` is the original variant's top-level root (the `top_root` column), absent if
  there was no manifest. `pipeline_version` is the version that ran the purge. Times have second
  precision.
- It is stored in its own table, which nothing deletes, and signed with the same keys as manifests.
  Offline verification has two outcomes only, ours and cannot say.

**Retention.**

- `expires_at` is fixed when it is set. `ttl_seconds` counts from the moment of the request (creation or
  `PATCH`), not from the asset's creation. Both must lie between a minute and ten years from now, so a
  typo cannot delete a video at once (`DELETE` does that on purpose). `PATCH` takes exactly one of
  `expires_at` and `ttl_seconds`; `null` for either clears the expiry.
- The tenant default is `asset_ttl_seconds` in the privacy settings. It is applied when an asset is
  created, so changing it does not change existing assets, and it is a full replacement like the other
  privacy settings (leaving it out clears it). Without a default and without a request, an asset has no
  expiry (ADR 0040).
- An asset in any state can expire, an unfinished upload included. The worker role's retention job runs
  every five minutes, so deletion can lag the expiry by that long; it marks the asset `deleting` and
  queues the purge in one transaction, like `DELETE` (reason `retention`).
- The access trail and the anomaly events are deleted after `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS`
  (default 90, bounds 1 to 3650): whole monthly partitions whose range ends before the cutoff date are
  dropped, older rows of the remaining partition and of `playback_events` are deleted in batches.
  Events go whether or not M7's delivery worker has delivered them, so that worker must run well inside
  the window.
- The two access-log partition functions become `SECURITY DEFINER` with the migrating session's
  `search_path`, so any role the service connects as can create and drop partitions (the follow-up
  "make access-log partition creation work from any role"). `EXECUTE` is revoked from `PUBLIC`, because
  any role that could call the drop function could erase the access trail. The owner, which is the
  service role when the service runs its own migrations, keeps it. A deployment whose service connects
  as a role other than the one that ran the migrations grants `EXECUTE` on both functions to that role.

**Not covered, flagged.** `audit_events` and `playback_sessions` (which holds the viewer ID, no address)
have no retention window. ADR 0040 names neither; they should get one before v1.0.0.

## Consequences

- A client that polls `GET` after `DELETE` sees `deleting`, then `deleted`; the record is then fetchable.
- Operators watch for dead-lettered `asset.delete` jobs: the asset stays `deleting` and its data stays
  encrypted until the job is retried.
- The in-flight wait can delay a deletion by up to the length of a transcode.
