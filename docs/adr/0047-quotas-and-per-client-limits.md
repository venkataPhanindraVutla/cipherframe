# 0047. Quotas and per-client limits

- Status: Accepted (flagged for owner review)
- Date: 2026-11-15
- Gate: none (M7-6)
- Deciders: implementer; the owner reviews the choices below

## Context

M7-6 limits what one tenant, and optionally one of its clients, can use: storage bytes, monthly
transcode minutes, concurrent playback sessions and control-plane request rates. The brief fixes the
shape (limits per tenant with lower per-client overrides, an admin API with a usage endpoint, stable
problem codes, 429 with `Retry-After`, no metrics until gate P14) and leaves the rest open: what
"unlimited" means, how usage is measured, where each limit is enforced and what a refusal looks like,
how racing requests are stopped and how the rate limit behaves with more than one instance. Each
choice below took the conservative option.

## Decisions

**Nothing is limited by default.** A tenant with no `tenant_quotas` row, and a limit column that is
`NULL`, is unlimited. Quotas are opt-in, so an upgrade changes no behaviour, and the per-viewer limit
of ADR 0028 (default 3) stays the only default cap. A limit is at least 1; there is no "0 means
unlimited" (unlike `max_sessions_per_viewer`), a field left out is how a limit is removed.

**Tenant limits, lower client overrides, the lower one wins.** `PUT /v1/quotas` sets the tenant's
limits; `PUT /v1/clients/{id}/quotas` sets a client's overrides. Both are full replacements, like the
playback settings. The effective limit for a client is the lower of the two, so lowering the tenant's
limit later takes effect for every client without touching their rows. Setting an override above the
tenant's current limit is `invalid_request` (an override that cannot do anything is a mistake to
surface); the check is made when the override is set, and a later lowering of the tenant limit keeps
the stored override but the lower number applies. The admin scope is required, like the other settings
endpoints. A client of another tenant is `not_found`.

**Storage is measured from the registries, never by listing storage.** Usage is the sum of
`assets.size_bytes` (the declared source size, which commit verifies against the object) and of every
`asset_artifacts` row in the delivery bucket (playlists, init and media segments, posters, subtitles,
the masked variant), over the tenant's assets, or over the assets one client created. An asset stops
counting when its purge completes (`state = 'deleted'`; while it is `deleting` it still holds its
bytes) and an aborted upload stops counting (its source objects are removed on abort). A failed
asset keeps counting its source, because the source is kept. The declared size counts from creation, so
an upload in progress holds its room.

**Storage is enforced at asset creation and again at commit, not during processing.** Creation checks
tenant and client usage plus the declared size; commit checks usage (the asset itself left out) plus
the verified size, because room may have been used since creation (other assets' output, or a limit
lowered meanwhile). A refused commit leaves the asset `uploading`; the client frees room or raises the
limit and commits again. Delivery bytes appear while the pipeline runs and are not checked there:
failing a half-finished transcode over its output size would waste the work and leave partial output
to clean, so the overshoot is bounded by one asset's output and the next creation or commit sees it.

**Transcode minutes are charged when processing starts, once the duration is known, and an
over-quota asset fails.** The duration is only known after the worker has downloaded and probed the
source, so the API role cannot refuse at commit without running FFprobe. The `asset.process` job
charges `duration` (milliseconds) right after validation and before any transcode work. If the charge
would pass the tenant's or the client's monthly limit the charge is not recorded and the asset fails
for good with `failure_code` `quota_transcode_minutes` (the job is cancelled, no retry can help until
the month turns or the limit is raised; the client sees the failure on the asset and in the
`asset.failed` webhook). The alternative, holding the job and retrying, would leave assets stuck in
`processing` with no signal. The commit request itself is not refused, so a client that wants to know
before uploading reads `GET /v1/usage`. Each asset is charged once (`transcode_charges` has the asset
as primary key), so a retried job costs nothing more, and a charge stays when the asset later fails
(the work was started). The month is the calendar month (UTC) of the charge. The masked variant is
the same source and is not charged again.

**Concurrent sessions are counted over active sessions and checked at the one creation path.** A
session counts while it is `active`, not past its expiry and not idle past the tenant's idle timeout
(the definition the per-viewer limit already uses). API-key, JWT and callback sessions all end in
`playback.Service.CreateSession`, so the check lives there and covers the browser paths on the edge.
Browser-started sessions have no client (ADR 0031), so they count toward the tenant's limit only and
a client's override counts only the sessions its own keys made. The refusal is `409 quota_exceeded`
with `limit` `concurrent_sessions`, not `session_limit`: that code means "this viewer has too many"
and a player may handle it differently from "the tenant is full". It is recorded in the access trail
as a denied creation like `session_limit` and raises no anomaly signal.

**Racing requests are stopped with one per-tenant advisory lock, taken only when a limit applies.**
Storage at creation and commit, session creation and the transcode charge each run their usage read
and their write in one transaction that holds `pg_advisory_xact_lock` on the tenant's quota key,
after reading the limits through that same transaction (so nothing takes a second pool connection
while the lock is held). A tenant with no relevant limit never takes the lock. Session creation takes
the viewer lock first and the tenant lock second, always in that order. Row locks on the quota row were
the alternative; they need a row to exist before the first limit is set and would lock the settings
row that an admin edits. The cost is that creations of one tenant with a limit serialise on a short
critical section.

**Request rates are a per-process token bucket, per API key.** The limit is the key's effective
`requests_per_minute` (tenant, lowered by the client's override). Each key has a bucket of capacity
`requests_per_minute` refilling at `requests_per_minute / 60` tokens a second: a minute's worth can be
used at once, and a steady client may use the limit evenly. It applies to every authenticated
`/v1/` operation of the api listener, right after authentication and before scope checks and body
decoding, so a key probing operations it may not call is limited too; a request that does not
authenticate is never counted. The state is in memory, so **the limit is per api process instance**:
N instances allow a key up to N times the limit. A shared limit would put a database or cache write on
every request; that is for the operations milestone if it is wanted. Limits are read at most every 15
seconds per key, so a change takes up to 15 seconds to apply, and a failure to read them lets the
request through (a database blip must not stop the control plane; the rest of the request needs the
database anyway). Idle keys are dropped after ten minutes. The answer is `429 rate_limited` with
`Retry-After` in whole seconds, at least 1, the time until the next token. The edge listener has its
own per-session limits (ADR 0028) and is not covered.

**`quota_exceeded` is a 409 and names the limit.** 429 would invite clients and proxies to retry, and a
retry cannot succeed until usage or limits change. 409 matches `session_limit` and `asset_not_ready`.
The problem has a `limit` member (`storage_bytes`, `transcode_minutes_per_month`, `concurrent_sessions`,
`requests_per_minute`) and a fixed detail that says whether the tenant's or the client's limit was hit;
it never carries a usage figure, a limit value or anything about another client or tenant.

**The usage endpoint reports the caller's tenant, or one of its clients.** `GET /v1/usage` returns the
used figure next to the effective limit for storage bytes, transcode milliseconds this month (the limit
converted from minutes), active sessions, and the request limit in force; with `?client_id=` it is the
client's own usage against the lower of its override and the tenant's limit. Request counts are in
memory per instance and are not reported. Usage comes from the same queries the checks use, so the
endpoint and the enforcement cannot disagree.

**Metrics wait for P14.** The plan says quotas are exposed "via API and metrics". The API is here; the
metrics (usage and refusals per tenant) are recorded as a follow-up in the roadmap because the
observability stack and its labelling rules (tenant cardinality) are gate P14.

## Consequences

- Operators and tenant admins can cap storage, processing, sessions and request rates, and read usage,
  with nothing changing for a tenant that sets nothing.
- Lowering a limit never removes data or ends sessions; it refuses what comes next. A tenant can be
  over a limit it just lowered.
- A transcode refusal shows up as a failed asset after the upload, not as a refused request. A client
  that must avoid that checks `GET /v1/usage` first.
- Storage can exceed its limit by the output of the assets that were processing at the time.
- Multiple api instances multiply the request rate limit; a changed limit takes up to 15 seconds to
  reach a running instance.
- Not covered: per-asset or per-day limits, soft limits and warnings, a webhook when a limit is hit,
  limits on the edge listener, and billing. Revisit the rate limit when a shared limiter is wanted and
  the storage rule if processing output becomes large enough for the overshoot to matter.
