# 0045. Webhooks: outbox, signing, retries and replay

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (M7-5; the signing scheme is [ADR 0029](0029-jwt-and-signed-callback-authorization.md)'s)
- Deciders: implementer; the owner reviews the choices below

## Context

M7-5 delivers Cipherframe's events (`asset.ready`, `asset.failed`, `asset.deleted`, `session.revoked`,
`session.anomaly`, `retention.expired`) to HTTPS endpoints a tenant registers. The brief fixes the
signing scheme (Standard Webhooks, as the viewer callback already uses), the SSRF-guarded client, an
outbox written with the state change, retries over about a day with a dead-letter list, a replay API
and retention in the access-trail window. It leaves open how events are written, how delivery runs,
what the schedule is, what the payloads hold and what replay means. Each choice below took the
conservative option.

## Decisions

**Events are written by database triggers, in the transaction of the change.** Triggers on
`assets.state`, on `playback_sessions.state` (to `revoked`) and on `INSERT` into `playback_events` call
`webhook_emit`, which writes one `webhook_events` row and one `webhook_deliveries` row per enabled
endpoint of the tenant whose filter matches. Alternatives were a call at each Go site (a dozen sites
across the pipeline, uploads, purge, playback, anomaly and retention; a new path would silently miss
events) and a River job per event (a job exists only if the change committed, but it carries no
tenant-visible state to list or replay). A trigger covers every current and future path, including the
ones the brief names as "edge revocation" (the anomaly auto-revoke) and the purge's revocation of an
asset's sessions, and there is no state in which the change committed and the event did not. The cost is
logic in SQL that a Go reader has to know about; the functions are `SECURITY DEFINER` (so a limited
service role needs no access to the webhook tables), `webhook_emit` is not executable by `PUBLIC`, and
the payload holds raw UUIDs which the delivery worker renders as prefixed IDs.

**Where each event fires.** `asset.ready` and `asset.failed` on the transition (an aborted upload is an
`asset.failed` with `failure_code` `upload_aborted`). `retention.expired` when the retention job starts
the deletion of an asset whose time-to-live ran out; `asset.deleted` when the purge finishes (so a
retention deletion sends both, in that order, and a requested deletion only the second).
`session.revoked` for every session that changes to revoked, one event per session, including each one
revoked because its asset is being deleted and each one an automatic revoke caught. Sessions that end or
expire do not send anything. `session.anomaly` for each stored anomaly event.

**Anomalies are folded into the new outbox.** The alternative was delivering from `playback_events` with
the `delivered_at` column M4 left for it. One outbox means one delivery path, one retry policy and one
place to list and replay; the anomaly's webhook event reuses the `playback_events` ID, so the events API
and a delivery name the same event. `playback_events.delivered_at` is left in place and is never set;
its partial index (`playback_events_undelivered_idx`) is dropped, since it would only grow.

**Only matching endpoints at that moment.** An event is written only when at least one enabled endpoint
matched, and deliveries are created with it. An endpoint registered later does not receive older events,
and deliveries of an endpoint that was disabled when the event happened do not exist. A disabled endpoint
keeps the deliveries it already has pending; they wait and go out when it is enabled again.

**Delivery is a polling worker over the delivery table, not River jobs.** Every two seconds the worker
role claims up to 32 due deliveries (`FOR UPDATE SKIP LOCKED`, and the claim pushes `next_attempt_at`
two minutes out as a lease), attempts them concurrently and settles each with the attempt record in one
transaction. A River job per delivery would put the retry state in a table that is not tenant-scoped and
has no status filter, so the delivery list, the dead-letter list and replay would need a second table
kept in step. One table is the source of truth. Any number of workers may run it. A worker that crashes
mid-attempt leaves the delivery claimed; it is due again when the lease ends and the lost attempt is not
counted, so delivery is at-least-once and a receiver deduplicates on the event ID. Latency from commit
to first attempt is about two seconds.

**Signing and request.** `POST`, `Content-Type: application/json`, `User-Agent: cipherframe-webhooks`,
`webhook-id` (the event's UUID, also the payload's `id`, identical on every attempt and every replay),
`webhook-timestamp` (fresh for every attempt, so a retry a day later is inside a receiver's replay
window) and `webhook-signature` (`v1,` and the base64 HMAC-SHA256 of `id.timestamp.body`), made by the
callback's own `viewerauth.Signature` helpers; the test suite checks them against the published
Standard Webhooks vector. The body is rendered once from the stored event, with sorted keys, so every
attempt signs the same bytes.

**Secrets.** One 32-byte secret per endpoint, shown as `whsec_<base64>` once, at creation and at
rotation, and stored wrapped by the key provider with `viewerauth.SecretBox`, bound to the tenant, the
secret's version and a purpose that names the endpoint (`webhook.endpoint_secret:whe_...`), so an
envelope copied to another endpoint of the same tenant does not open. A rotation keeps the previous
secret signing for 24 hours (two signatures in the header), the same window as the viewer callback. No
call returns a secret again; there is no "get secret".

**Schedule.** Twelve attempts, a 10-second timeout each. The waits after attempts 1 to 11 are 10 s,
30 s, 1 min, 5 min, 15 min, 30 min, 1 h, 2 h, 4 h, 6 h and 8 h (21 h 52 min in all), each spread by up to
20% either way. Every response that is not 2xx is a failure and is retried, 4xx and `410` included: a
receiver that is misconfigured today is often fixed within the day, and dead-lettering on the first `404`
would lose events a tenant can still recover. A redirect is never followed and counts as a failure
(`redirect`). After the twelfth failure the delivery is `dead`.

**What an attempt records.** The attempt number and time, the status code (none without a response), the
duration in milliseconds, a failure class (`status`, `timeout`, `network`, `redirect`,
`blocked_address`, `bad_url`) and an excerpt: the first KiB of the response reduced to printable ASCII on
one line and cut to 200 characters. Never headers, never more of the body. Neither the URL nor the
secret is logged anywhere; the log line of an attempt names the tenant, endpoint and event IDs, the kind
and the failure class.

**Replay.** `POST /v1/webhook-deliveries/{id}/replay` puts a delivery that is `succeeded` or `dead` back
to `pending` with zero attempts and a fresh budget (a pending one is `409`);
`POST /v1/webhook-endpoints/{id}/replay-dead` does that for every dead delivery of an endpoint. The
build plan's "replay command" is this API; the CLI comes in M8. The event ID stays the same, so the
receiver deduplicates. The attempts of earlier runs stay listed.

**Endpoints.** HTTPS only, no credentials, at most 2048 characters, at most 10 per tenant (counted under
a per-tenant advisory lock). The URL is checked at registration and update by `outbound.CheckURL`, which
refuses an IP literal in a blocked range; that check is for a clear error, and the authority is the
dial-time check of `internal/outbound` on every request, so a name that later resolves to a private
address is refused (`blocked_address`). There is no setting that allows plain HTTP: none exists
elsewhere in the service, and a development receiver can use a TLS test certificate or a tunnel. The
operations use the `webhooks:manage` scope that already exists (an admin key has it).

**Payloads.** `{id, type, occurred_at, tenant_id, data}`. `data` holds asset IDs (`ast_...`), states and
codes (`failure_code`, the deletion `reason`, `expires_at`), the anomaly `kind`, its small-integer
`detail`, and for the two session kinds the viewer ID, the 8-character session fingerprint the access
trail uses and, for a revocation, the `reason` it was made with. No viewer address, user agent, file
name, key, token or session ID is ever in an event. The viewer ID is the tenant's own pseudonym and the
revoke reason is text the tenant (or a system reason such as `auto:key_replay` or `asset_deleted`) wrote;
both go back to the tenant that supplied them.

**Retention.** Webhook events, with their deliveries and attempts (`ON DELETE CASCADE`), are deleted
after `CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS` (default 90), by the existing retention job, whatever their
state: a dead delivery older than the window can no longer be replayed, and a delivery stuck pending
behind a disabled endpoint is dropped with it. Deleting an endpoint deletes its deliveries.

## Consequences

Easier: every state change is covered without touching the code that makes it; one table answers the
admin API; the signing code has one implementation.

Harder or not covered:

- There is no ordering guarantee between events or between retries, and no exactly-once delivery: a
  receiver deduplicates on the ID and orders by `occurred_at`.
- A burst (a bulk revocation of thousands of sessions) writes one event per session per endpoint and is
  delivered 32 at a time every two seconds or faster while a full batch keeps coming; there is no
  per-endpoint rate limit or circuit breaker yet. Quotas arrive with M7-6.
- A key-provider outage stops delivery (the secrets cannot be opened) without consuming attempts; the
  deliveries go out when it returns.
- Event and delivery rows are removed by age, so the dead-letter list is a window of 90 days, not an
  archive.
- Revisit if a tenant needs ordered delivery, per-endpoint throttling or payload versioning (there is
  none yet: the envelope has no version field, and a breaking change would need one).
