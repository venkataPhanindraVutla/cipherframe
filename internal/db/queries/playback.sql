-- name: GetPlaybackSettings :one
SELECT * FROM playback_settings WHERE tenant_id = $1;

-- name: UpsertPlaybackSettings :one
INSERT INTO playback_settings (
    tenant_id, token_ttl_seconds, heartbeat_interval_seconds, idle_timeout_seconds,
    session_max_seconds, max_sessions_per_viewer, key_fetches_per_token, key_requests_per_minute,
    allowed_origins, token_in_url, updated_at
) VALUES (
    sqlc.arg(tenant_id)::uuid, sqlc.arg(token_ttl_seconds)::integer,
    sqlc.arg(heartbeat_interval_seconds)::integer, sqlc.arg(idle_timeout_seconds)::integer,
    sqlc.arg(session_max_seconds)::integer, sqlc.arg(max_sessions_per_viewer)::integer,
    sqlc.arg(key_fetches_per_token)::integer, sqlc.arg(key_requests_per_minute)::integer,
    sqlc.arg(allowed_origins)::text[], sqlc.arg(token_in_url)::boolean, sqlc.arg(at)::timestamptz
)
ON CONFLICT (tenant_id) DO UPDATE SET
    token_ttl_seconds          = EXCLUDED.token_ttl_seconds,
    heartbeat_interval_seconds = EXCLUDED.heartbeat_interval_seconds,
    idle_timeout_seconds       = EXCLUDED.idle_timeout_seconds,
    session_max_seconds        = EXCLUDED.session_max_seconds,
    max_sessions_per_viewer    = EXCLUDED.max_sessions_per_viewer,
    key_fetches_per_token      = EXCLUDED.key_fetches_per_token,
    key_requests_per_minute    = EXCLUDED.key_requests_per_minute,
    allowed_origins            = EXCLUDED.allowed_origins,
    token_in_url               = EXCLUDED.token_in_url,
    updated_at                 = EXCLUDED.updated_at
RETURNING *;

-- name: LockPlaybackViewer :exec
-- Serialises session creation for one (tenant, viewer) until the transaction ends, so the count
-- below and the insert that follows cannot interleave with another creation. Two different viewers
-- that hash to the same lock only wait for each other.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: EndStalePlaybackSessions :execrows
-- Lazily ends one viewer's sessions that are idle past the timeout or past their expiry.
UPDATE playback_sessions SET state = 'ended', ended_at = sqlc.arg(now)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND viewer_id = sqlc.arg(viewer_id)::text
  AND state = 'active'
  AND (last_heartbeat_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(idle_seconds)::integer)
       OR expires_at <= sqlc.arg(now)::timestamptz);

-- name: CountActivePlaybackSessions :one
SELECT count(*) FROM playback_sessions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND viewer_id = sqlc.arg(viewer_id)::text
  AND state = 'active'
  AND last_heartbeat_at > sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(idle_seconds)::integer)
  AND expires_at > sqlc.arg(now)::timestamptz;

-- name: InsertPlaybackSession :one
-- The asset must belong to the tenant and be ready; otherwise no row is inserted.
INSERT INTO playback_sessions (
    id_hash, tenant_id, client_id, asset_id, viewer_id, state, created_at, last_heartbeat_at, expires_at
)
SELECT sqlc.arg(id_hash)::bytea, a.tenant_id, sqlc.arg(client_id)::uuid, a.id, sqlc.arg(viewer_id)::text,
       'active', sqlc.arg(now)::timestamptz, sqlc.arg(now)::timestamptz, sqlc.arg(expires_at)::timestamptz
FROM assets a
WHERE a.id = sqlc.arg(asset_id)::uuid AND a.tenant_id = sqlc.arg(tenant_id)::uuid AND a.state = 'ready'
RETURNING *;

-- name: GetPlaybackSession :one
SELECT * FROM playback_sessions WHERE tenant_id = $1 AND id_hash = $2;
