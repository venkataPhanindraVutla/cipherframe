-- name: InsertExternalTask :one
INSERT INTO external_tasks (id, kind, envelope, max_attempts, river_job_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetExternalTask :one
SELECT * FROM external_tasks
WHERE id = $1;

-- name: ClaimExternalTask :one
-- Claim protocol (spec/jobs/README.md). A pending row, or a leased row whose lease has expired and
-- that still has an attempt left, is taken by the first caller to lock it. Reclaiming an expired
-- lease counts as a new attempt, so a task that crashes its workers cannot loop forever.
UPDATE external_tasks AS t
SET state       = 'leased',
    lease_owner = sqlc.arg(owner)::text,
    lease_until = now() + make_interval(secs => sqlc.arg(lease_seconds)::float8),
    attempts    = t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END,
    envelope    = jsonb_set(t.envelope, '{attempt}',
                      to_jsonb(t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END + 1)),
    updated_at  = now()
WHERE t.id = (
    SELECT c.id FROM external_tasks AS c
    WHERE c.kind = ANY(sqlc.arg(kinds)::text[])
      AND (c.state = 'pending'
           OR (c.state = 'leased' AND c.lease_until < now() AND c.attempts + 1 < c.max_attempts))
    ORDER BY c.created_at, c.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;

-- name: HeartbeatExternalTask :execrows
-- Extends the lease only for the worker that holds it.
UPDATE external_tasks
SET lease_until = now() + make_interval(secs => sqlc.arg(lease_seconds)::float8),
    updated_at  = now()
WHERE id = sqlc.arg(id) AND state = 'leased' AND lease_owner = sqlc.arg(owner)::text;

-- name: CompleteExternalTask :execrows
-- Records a succeeded result, only for the worker that holds the lease.
UPDATE external_tasks
SET state        = 'succeeded',
    result       = sqlc.arg(result)::jsonb,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = now()
WHERE id = sqlc.arg(id) AND state = 'leased' AND lease_owner = sqlc.arg(owner)::text;

-- name: FailExternalTask :execrows
-- Records a failed result, only for the worker that holds the lease.
UPDATE external_tasks
SET state        = 'failed',
    result       = sqlc.arg(result)::jsonb,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = now()
WHERE id = sqlc.arg(id) AND state = 'leased' AND lease_owner = sqlc.arg(owner)::text;

-- name: RequeueExternalTask :execrows
-- Used by the Go await job after a retryable failure: back to pending with the next attempt number.
UPDATE external_tasks
SET state        = 'pending',
    attempts     = attempts + 1,
    envelope     = jsonb_set(envelope, '{attempt}', to_jsonb(attempts + 2)),
    result       = NULL,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = NULL
WHERE id = sqlc.arg(id) AND state = 'failed' AND attempts + 1 < max_attempts;

-- name: ExpireExternalTask :execrows
-- Used by the Go await job when a lease has expired and no attempt is left: the task fails.
UPDATE external_tasks
SET state        = 'failed',
    result       = sqlc.arg(result)::jsonb,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = now()
WHERE id = sqlc.arg(id) AND state = 'leased' AND lease_until < now() AND attempts + 1 >= max_attempts;
