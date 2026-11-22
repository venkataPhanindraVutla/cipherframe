# Disaster recovery

What to back up, in which order to restore, and what each loss costs. Read the first section before
you design anything else.

> **Losing the key-encryption key (KEK), or access to the KMS key that holds it, makes every asset
> permanently unreadable. There is no recovery path and the project cannot help.**
>
> Content keys are stored only wrapped by the KEK. Segments are AES-128 ciphertext. Without the KEK
> nobody (not the operator, not the project, not a support request) can unwrap a content key, so the
> ciphertext in the bucket is noise. This is the same property that makes crypto-shredding work
> ([privacy.md](privacy.md)); it cannot be switched off for the assets you want to keep. The source
> recordings are the only way back, and only if you kept them somewhere else (the source bucket
> holds them until deletion or the tenant's time-to-live removes them).

## What to back up

| What | Where it lives | Back up how | If it is lost |
|---|---|---|---|
| **KEK** (or access to it) | The key provider: AWS KMS key, GCP Cloud KMS key, Vault or OpenBao Transit key, or for `local` the `CIPHERFRAME_KMS_LOCAL_KEKS` value | Provider-side: KMS key deletion protection and the longest deletion waiting period, multi-region or replica keys where the provider has them, Vault snapshots with the seal keys kept apart. For `local` (development only): copy the value to a secret store | Every asset is permanently unreadable. See [KEK rotation versus KEK loss](#kek-rotation-versus-kek-loss). |
| **Postgres** | Everything the service knows: tenants, API key hashes, assets, wrapped content keys, wrapped signing keys, manifests, deletion records, sessions, webhooks, the job queue | Continuous WAL archiving with periodic base backups (point in time recovery), or your provider's equivalent. Test a restore | Assets, wrapped content keys and manifests are gone: the bucket is unreadable even with the KEK. |
| **Delivery bucket** | Encrypted segments, playlists, subtitles, thumbnails | Bucket versioning plus cross-region replication, or a periodic copy | Playback stops. If Postgres and the KEK survive, re-process from the source (below); if the source is also gone the asset is lost. |
| **Source bucket** | The original uploads (ADR 0040) | Same, with the privacy caveat below | Re-processing is impossible; delivery objects are the only copy. |
| **Playback token keys** | `CIPHERFRAME_PLAYBACK_TOKEN_KEYS` and `..._CURRENT` | Secret store | Issued tokens stop verifying (a viewer starts a new session). Make new keys and set both variables. Nothing is lost permanently. |
| **API key peppers** | `CIPHERFRAME_API_KEY_PEPPERS` and `..._CURRENT` | Secret store, kept apart from the Postgres backup | See [Losing a pepper](#losing-a-pepper). |
| **Webhook and callback secrets** | Postgres, wrapped by the KMS provider (ADR 0045, ADR 0029) | Covered by the Postgres backup, and by the KEK | With the KEK they unwrap. Without it they are lost like everything else; endpoints need a new secret (`rotate-secret`) and the receivers must be told. |
| **Integrity signing keys** | Postgres, as wrapped seeds ([integrity.md](integrity.md#signing-keys)) | Covered by the Postgres backup, and by the KEK. **Also keep a copy of the published key set** (`GET /.well-known/cipherframe-keys.json`) | See [Losing the signing keys](#losing-the-signing-keys). |
| **Configuration** | Environment, Helm values, Terraform state ([ADR 0054](adr/0054-operations-and-release-tooling.md)) | Your infrastructure repository and state backend | Rebuildable, but KEK and key identifiers must be exact. |
| **Metrics scrape token, OTLP credentials** | Environment | Secret store | Reissue. No data is lost. |

Keep the **KEK access and the Postgres backup under different credentials**. A backup that opens
with the credential that also opens the KEK is a copy of everything.

**Backups and deletion.** A Postgres backup contains the wrapped content key of an asset that was
deleted afterwards. Together with a bucket copy that still holds the ciphertext, that is a way to
read a deleted recording again. So: give backups of the database and of the buckets a retention
period that fits the promise you make about deletion, and after any restore **repeat the deletions**
that happened since the backup (the `asset.deleted` webhook events your systems received, and the
`asset_deletion_records` you exported, list them). Cipherframe does not do this
for you.

## Restore order

1. **KMS access first.** Confirm the key provider and KEK identifiers named in the configuration are
   usable with the new credentials: wrap and unwrap a test value. Nothing else matters until this
   works. If you restore into a new account or region, the KEK must be the same key (or an imported
   copy that unwraps old envelopes). A *new* key cannot read old data.
2. **Secrets.** Restore pepper, playback token key and metrics token sets from your secret store.
3. **Postgres.** Restore to the chosen point in time. Then run `cipherframe-server migrate` with the
   release you are restoring under, so the schema matches the code; do not run a release older than
   the schema in the backup.
4. **Buckets.** Restore or replicate the delivery bucket, then the source bucket. Names must match
   the configuration, and the two must differ.
5. **Start `api` and `worker` first, `edge` last.** The worker resumes the queue. At start the
   server checks that every KEK version a content key refers to is configured and refuses to start
   otherwise: that refusal is the signal that step 1 or 2 is wrong, not a bug.
6. **Check.** `cipherframe-server admin kms-usage` (content keys per KEK version), a `verify` of a
   few assets against the published key set, and a playback of a test asset through edge.
7. **Reconcile.** Objects written after the backup are missing from Postgres, and rows written after
   the bucket copy point at missing objects. Assets whose objects are gone can be re-processed from
   the source if it survives; others must be re-uploaded. Repeat deletions as described above.
8. **Only then** open edge to traffic and tell webhook receivers events may repeat (delivery is at
   least once, ADR 0045).

## RPO and RTO

Cipherframe sets no targets of its own. What it adds to your numbers:

- **RPO** is the weaker of the Postgres and bucket copies, plus: an upload in flight at the time of
  the failure is lost. The anchoring and
  anomaly counters are best-effort and may lose up to a flush interval (about 30 seconds).
- **RTO** is dominated by the Postgres restore and, only if you must re-process, by transcoding
  time; re-processing is a worker job per asset (ADR 0027) and is slow compared with a restore. Plan
  for the bucket to come back from a copy, not from the source.
- Playback needs Postgres, the bucket and the KMS at once (fail closed, I11). A KMS outage is
  `503 dependency_unavailable`, not data loss: it ends when the provider returns.

## KEK rotation versus KEK loss

| | Rotation | Loss |
|---|---|---|
| What happens | A new KEK version wraps new keys; `kms-rewrap` moves old keys across ([encryption.md](encryption.md#rotation-and-re-wrap)) | The KEK, or access to it, is gone |
| Content | Unchanged, no re-encryption | **Unreadable for ever** |
| Old version | Kept until `kms-usage` shows no key uses it, then disabled at the provider | Not applicable |
| Recovery | Not needed | **None.** Re-upload from your own copies of the originals |

Rules that keep rotation from becoming loss:

- Never disable or destroy an old KEK version while a content key, a signing key envelope, a webhook
  secret or a callback secret is still wrapped under it. `kms-rewrap` moves content keys only; the
  other envelopes are re-wrapped by rotating the secret or the signing key themselves
  (see [integrity.md](integrity.md#signing-keys), [api.md](api.md)).
- Turn on the provider's deletion protection and the longest waiting period for scheduled key
  deletion, and alert on any key-deletion request.
- A KMS key deleted by mistake can be recovered only during the provider's waiting window. After it,
  see the first box.

## Losing the signing keys

The wrapped seeds are in Postgres and open with the KEK, so a Postgres restore with the KEK brings
them back. If the seeds are lost but you have the **published key set**:

- **Old manifests and deletion records still verify.** Verification needs only the public key, and
  the key set is public. Keep a copy of it (and of any RFC 3161 timestamp tokens, which prove when a
  manifest existed independently of your keys).
- **The lost key cannot sign again, and signing fails closed.** Rows whose seed cannot be unwrapped
  are not replaced automatically (the service creates a key only when the deployment has none), so
  new manifests fail with `503 dependency_unavailable` until the database holds a usable current key.
  Recovering from that state is not automated; it is listed in the roadmap follow-ups. Records the
  lost key signed keep their signature and are not re-signed.
- If you have **no** copy of the public keys either, the signatures cannot be checked by anyone, and
  your signed deletion records stop being evidence. Keep the key set in a place you control.
- A leaked key is a different case: rotate, retire, and read the limits in
  [threat-model.md](threat-model.md). The key set does not yet mark a key "revoked as compromised".

## Losing a pepper

API keys are stored as `HMAC-SHA256(pepper, secret)` with the pepper version beside the hash
(ADR 0016). Without the pepper of a version the service cannot check any key of that version.

- The keys are not lost, and nothing else breaks: **every API key of that version stops working.**
  The service refuses to start while a stored key refers to a pepper version that is not configured.
- Recovery: configure a new pepper version, start the service with the old version marked removed
  after revoking, and have each client create a new key. The first admin key must come from the
  bootstrap path ([usage.md](usage.md)), which needs database access.
- A pepper that is **leaked** (and the key hashes with it) lets an attacker test guesses against the
  hashes offline; the secrets are 256 random bits, so guessing is not practical, but rotate the
  pepper and keys anyway.

## Exercise it

Rehearse in a scratch environment at least once before launch: restore Postgres and the buckets to a
second deployment with the same KEK, run the checks in step 6, then run the same restore against a
**different** KEK and confirm playback fails closed. The second result is the one worth seeing with
your own eyes.
