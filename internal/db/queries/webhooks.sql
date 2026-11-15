-- Webhooks (M7-5, ADR 0045). The events are written by triggers (migration 00024); everything here
-- reads and settles them.

-- name: LockWebhookEndpoints :exec
-- Serialises changes to one tenant's endpoint set until the transaction ends (the cap is counted).
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: CountWebhookEndpoints :one
SELECT count(*) FROM webhook_endpoints WHERE tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: InsertWebhookEndpoint :one
INSERT INTO webhook_endpoints (id, tenant_id, url, events, enabled, secret_envelope, secret_version, created_at, updated_at)
VALUES (sqlc.arg(id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(url)::text, sqlc.arg(events)::text[],
        sqlc.arg(enabled)::boolean, sqlc.arg(secret_envelope)::bytea, 1, sqlc.arg(at)::timestamptz, sqlc.arg(at)::timestamptz)
RETURNING *;

-- name: ListWebhookEndpoints :many
SELECT * FROM webhook_endpoints WHERE tenant_id = sqlc.arg(tenant_id)::uuid ORDER BY created_at, id;

-- name: GetWebhookEndpoint :one
SELECT * FROM webhook_endpoints WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid;

-- name: UpdateWebhookEndpoint :one
UPDATE webhook_endpoints SET
    url        = COALESCE(sqlc.narg(url)::text, url),
    events     = COALESCE(sqlc.narg(events)::text[], events),
    enabled    = COALESCE(sqlc.narg(enabled)::boolean, enabled),
    updated_at = sqlc.arg(at)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid
RETURNING *;

-- name: RotateWebhookEndpointSecret :one
-- Applies only while secret_version is still the one the new secret was made after, so two
-- concurrent rotations cannot share a version.
UPDATE webhook_endpoints SET
    prev_secret_envelope = secret_envelope,
    prev_secret_version  = secret_version,
    secret_envelope      = sqlc.arg(envelope)::bytea,
    secret_version       = sqlc.arg(version)::integer,
    secret_rotated_at    = sqlc.arg(at)::timestamptz,
    updated_at           = sqlc.arg(at)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid
  AND secret_version = sqlc.arg(version)::integer - 1
RETURNING *;

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid;

-- name: ClaimWebhookDeliveries :many
-- Takes up to max_rows due deliveries of enabled endpoints and pushes their next attempt out by the
-- lease, so another worker (or this one, after a crash) picks them up again only if this attempt
-- never settles. Returns everything one attempt needs.
WITH due AS (
    SELECT d.id FROM webhook_deliveries d
    JOIN webhook_endpoints e ON e.id = d.endpoint_id AND e.enabled
    WHERE d.state = 'pending' AND d.next_attempt_at <= sqlc.arg(now)::timestamptz
    ORDER BY d.next_attempt_at
    LIMIT sqlc.arg(max_rows)::integer
    FOR UPDATE OF d SKIP LOCKED
), claimed AS (
    UPDATE webhook_deliveries d SET next_attempt_at = sqlc.arg(now)::timestamptz + make_interval(secs => sqlc.arg(lease_seconds)::integer)
    FROM due WHERE d.id = due.id
    RETURNING d.id, d.tenant_id, d.event_id, d.endpoint_id, d.attempts
)
SELECT c.id, c.tenant_id, c.event_id, c.endpoint_id, c.attempts,
       ev.kind, ev.data, ev.occurred_at,
       e.url, e.secret_envelope, e.secret_version, e.prev_secret_envelope, e.prev_secret_version, e.secret_rotated_at
FROM claimed c
JOIN webhook_events ev ON ev.id = c.event_id
JOIN webhook_endpoints e ON e.id = c.endpoint_id;

-- name: InsertWebhookAttempt :exec
INSERT INTO webhook_attempts (delivery_id, tenant_id, number, at, status_code, duration_ms, error, excerpt)
VALUES (sqlc.arg(delivery_id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(number)::integer, sqlc.arg(at)::timestamptz,
        sqlc.narg(status_code)::integer, sqlc.arg(duration_ms)::integer, sqlc.narg(error)::text, sqlc.arg(excerpt)::text);

-- name: SettleWebhookDelivery :execrows
-- Records the outcome of an attempt on a delivery that is still pending and has not been replayed
-- since the attempt was claimed (a replay resets attempts, so this settle then does nothing).
UPDATE webhook_deliveries SET
    state           = sqlc.arg(state)::text,
    attempts        = attempts + 1,
    next_attempt_at = COALESCE(sqlc.narg(next_attempt_at)::timestamptz, next_attempt_at),
    last_status     = sqlc.narg(status_code)::integer,
    last_attempt_at = sqlc.arg(at)::timestamptz,
    completed_at    = CASE WHEN sqlc.arg(state)::text = 'pending' THEN NULL ELSE sqlc.arg(at)::timestamptz END
WHERE id = sqlc.arg(id)::uuid AND state = 'pending' AND attempts = sqlc.arg(attempts)::integer;

-- name: ListWebhookDeliveries :many
-- Newest first, keyset-paginated on (created_at, id): cursor_at is the exclusive upper bound of
-- created_at and cursor_id the largest uuid for the first page.
SELECT d.id, d.endpoint_id, d.event_id, ev.kind, d.state, d.attempts, d.last_status, d.last_attempt_at,
       d.next_attempt_at, d.completed_at, d.created_at
FROM webhook_deliveries d
JOIN webhook_events ev ON ev.id = d.event_id
WHERE d.tenant_id = sqlc.arg(tenant_id)::uuid
  AND (sqlc.narg(endpoint_id)::uuid IS NULL OR d.endpoint_id = sqlc.narg(endpoint_id)::uuid)
  AND (sqlc.narg(state)::text IS NULL OR d.state = sqlc.narg(state)::text)
  AND (d.created_at, d.id) < (sqlc.arg(cursor_at)::timestamptz, sqlc.arg(cursor_id)::uuid)
ORDER BY d.created_at DESC, d.id DESC
LIMIT sqlc.arg(max_rows)::integer;

-- name: GetWebhookDelivery :one
SELECT d.id, d.endpoint_id, d.event_id, ev.kind, d.state, d.attempts, d.last_status, d.last_attempt_at,
       d.next_attempt_at, d.completed_at, d.created_at
FROM webhook_deliveries d
JOIN webhook_events ev ON ev.id = d.event_id
WHERE d.tenant_id = sqlc.arg(tenant_id)::uuid AND d.id = sqlc.arg(id)::uuid;

-- name: ListWebhookAttempts :many
SELECT number, at, status_code, duration_ms, error, excerpt
FROM webhook_attempts
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND delivery_id = sqlc.arg(delivery_id)::uuid
ORDER BY id;

-- name: ReplayWebhookDelivery :execrows
-- Puts a settled delivery (succeeded or dead) back in the queue, with a fresh attempt budget.
UPDATE webhook_deliveries SET state = 'pending', attempts = 0, next_attempt_at = sqlc.arg(now)::timestamptz, completed_at = NULL
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid AND state <> 'pending';

-- name: ReplayDeadWebhookDeliveries :execrows
UPDATE webhook_deliveries SET state = 'pending', attempts = 0, next_attempt_at = sqlc.arg(now)::timestamptz, completed_at = NULL
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND endpoint_id = sqlc.arg(endpoint_id)::uuid AND state = 'dead';

-- name: DeleteWebhookEventsBefore :execrows
-- Retention (M7-5): one bounded batch of events (and, by cascade, their deliveries and attempts)
-- older than the cutoff.
DELETE FROM webhook_events
WHERE id IN (SELECT e.id FROM webhook_events e WHERE e.created_at < sqlc.arg(cutoff)::timestamptz ORDER BY e.created_at LIMIT sqlc.arg(batch)::integer);
