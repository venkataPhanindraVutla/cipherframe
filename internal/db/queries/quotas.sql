-- name: GetTenantQuotas :one
SELECT * FROM tenant_quotas WHERE tenant_id = $1;

-- name: UpsertTenantQuotas :one
INSERT INTO tenant_quotas (tenant_id, storage_bytes, transcode_minutes_per_month, concurrent_sessions, requests_per_minute, updated_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.narg(storage_bytes)::bigint, sqlc.narg(transcode_minutes_per_month)::integer,
        sqlc.narg(concurrent_sessions)::integer, sqlc.narg(requests_per_minute)::integer, sqlc.arg(at)::timestamptz)
ON CONFLICT (tenant_id) DO UPDATE SET
    storage_bytes = EXCLUDED.storage_bytes,
    transcode_minutes_per_month = EXCLUDED.transcode_minutes_per_month,
    concurrent_sessions = EXCLUDED.concurrent_sessions,
    requests_per_minute = EXCLUDED.requests_per_minute,
    updated_at = EXCLUDED.updated_at
RETURNING *;

-- name: GetClientQuotas :one
SELECT * FROM client_quotas WHERE tenant_id = $1 AND client_id = $2;

-- name: UpsertClientQuotas :one
-- The client must belong to the tenant; otherwise no row is written.
INSERT INTO client_quotas (client_id, tenant_id, storage_bytes, transcode_minutes_per_month, concurrent_sessions, requests_per_minute, updated_at)
SELECT c.id, c.tenant_id, sqlc.narg(storage_bytes)::bigint, sqlc.narg(transcode_minutes_per_month)::integer,
       sqlc.narg(concurrent_sessions)::integer, sqlc.narg(requests_per_minute)::integer, sqlc.arg(at)::timestamptz
FROM clients c
WHERE c.id = sqlc.arg(client_id)::uuid AND c.tenant_id = sqlc.arg(tenant_id)::uuid
ON CONFLICT (client_id) DO UPDATE SET
    storage_bytes = EXCLUDED.storage_bytes,
    transcode_minutes_per_month = EXCLUDED.transcode_minutes_per_month,
    concurrent_sessions = EXCLUDED.concurrent_sessions,
    requests_per_minute = EXCLUDED.requests_per_minute,
    updated_at = EXCLUDED.updated_at
RETURNING *;

-- name: LockQuota :exec
-- Serialises the checks and writes that must not interleave for one tenant (storage at creation and
-- commit, concurrent sessions, the transcode ledger) until the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 1));

-- name: StorageUsage :one
-- Source plus delivery bytes of the tenant's assets from the registries: the declared (and, after
-- commit, verified) source size in assets.size_bytes and every delivery object in asset_artifacts.
-- A deleted asset (its purge finished), an aborted upload and a dropped original (its source was
-- removed) do not count.
-- client_id narrows to the assets one client created; exclude_asset leaves one asset out (the commit
-- check adds its actual size back).
WITH counted AS (
    -- An original that asset.drop_source removed no longer occupies the source bucket.
    SELECT a.id, CASE WHEN a.source_deleted_at IS NULL THEN a.size_bytes ELSE 0 END AS size_bytes FROM assets a
    WHERE a.tenant_id = sqlc.arg(tenant_id)::uuid
      AND a.state <> 'deleted'
      AND NOT (a.state = 'failed' AND a.failure_code = 'upload_aborted')
      AND (sqlc.narg(client_id)::uuid IS NULL OR a.created_by_client_id = sqlc.narg(client_id)::uuid)
      AND (sqlc.narg(exclude_asset)::uuid IS NULL OR a.id <> sqlc.narg(exclude_asset)::uuid)
)
SELECT
    COALESCE((SELECT SUM(c.size_bytes) FROM counted c), 0)::bigint AS source_bytes,
    COALESCE((SELECT SUM(ar.size_bytes) FROM asset_artifacts ar JOIN counted c ON c.id = ar.asset_id
              WHERE ar.bucket = 'delivery'), 0)::bigint AS delivery_bytes;

-- name: DeleteTranscodeCharge :exec
-- A reprocess (H-4) takes back the failed run's charge so the new run charges the asset again, in the
-- month it runs in, and is refused if the limit is used up by then.
DELETE FROM transcode_charges WHERE asset_id = sqlc.arg(asset_id)::uuid AND tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: TranscodeUsage :one
-- Milliseconds of source charged in [from, until).
SELECT COALESCE(SUM(duration_ms), 0)::bigint AS duration_ms FROM transcode_charges
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND charged_at >= sqlc.arg(from_at)::timestamptz AND charged_at < sqlc.arg(until_at)::timestamptz
  AND (sqlc.narg(client_id)::uuid IS NULL OR client_id = sqlc.narg(client_id)::uuid);

-- name: InsertTranscodeCharge :execrows
-- One charge per asset: a retried job inserts nothing.
INSERT INTO transcode_charges (asset_id, tenant_id, client_id, duration_ms, charged_at)
SELECT a.id, a.tenant_id, a.created_by_client_id, sqlc.arg(duration_ms)::bigint, sqlc.arg(at)::timestamptz
FROM assets a
WHERE a.id = sqlc.arg(asset_id)::uuid AND a.tenant_id = sqlc.arg(tenant_id)::uuid
ON CONFLICT (asset_id) DO NOTHING;

-- name: CountTenantActiveSessions :one
-- Active sessions of the tenant, or of one client (an API-key session carries its client; a session
-- the viewer's browser started has none and counts toward the tenant only).
SELECT count(*) FROM playback_sessions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND (sqlc.narg(client_id)::uuid IS NULL OR client_id = sqlc.narg(client_id)::uuid)
  AND state = 'active'
  AND last_heartbeat_at > sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(idle_seconds)::integer)
  AND expires_at > sqlc.arg(now)::timestamptz;
