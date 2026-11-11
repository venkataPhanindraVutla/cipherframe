-- name: GetPlaybackSettings :one
SELECT * FROM playback_settings WHERE tenant_id = $1;

-- name: UpsertPlaybackSettings :one
INSERT INTO playback_settings (
    tenant_id, token_ttl_seconds, heartbeat_interval_seconds, idle_timeout_seconds,
    session_max_seconds, max_sessions_per_viewer, key_fetches_per_token, key_requests_per_minute,
    allowed_origins, token_in_url, delivery, updated_at
) VALUES (
    sqlc.arg(tenant_id)::uuid, sqlc.arg(token_ttl_seconds)::integer,
    sqlc.arg(heartbeat_interval_seconds)::integer, sqlc.arg(idle_timeout_seconds)::integer,
    sqlc.arg(session_max_seconds)::integer, sqlc.arg(max_sessions_per_viewer)::integer,
    sqlc.arg(key_fetches_per_token)::integer, sqlc.arg(key_requests_per_minute)::integer,
    sqlc.arg(allowed_origins)::text[], sqlc.arg(token_in_url)::boolean, sqlc.arg(delivery)::text,
    sqlc.arg(at)::timestamptz
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
    delivery                   = EXCLUDED.delivery,
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

-- name: GetPlaybackSessionTenant :one
-- Edge answers a CORS preflight, which carries no token, knowing only the session in the path.
SELECT tenant_id FROM playback_sessions WHERE id_hash = $1;

-- name: BumpPlaybackKeyWindow :one
-- Counts one key request in the session's fixed one-minute window, in one statement: a window
-- that is unset or at least a minute old restarts at now with a count of 1. The count is capped so
-- a flood cannot overflow it. Rejected requests are counted too (they cap hammering).
UPDATE playback_sessions SET
    key_window_start = CASE
        WHEN key_window_start IS NULL OR key_window_start <= sqlc.arg(now)::timestamptz - interval '1 minute'
        THEN sqlc.arg(now)::timestamptz ELSE key_window_start END,
    key_window_count = CASE
        WHEN key_window_start IS NULL OR key_window_start <= sqlc.arg(now)::timestamptz - interval '1 minute'
        THEN 1 ELSE LEAST(key_window_count + 1, 1000000) END
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id_hash = sqlc.arg(id_hash)::bytea
RETURNING key_window_start, key_window_count;

-- name: ReservePlaybackKeyFetch :one
-- Takes one of a token's key fetches, or returns no row when the token has used max_fetches. The
-- check and the increment are one statement, so concurrent requests cannot exceed the bound.
INSERT INTO playback_key_fetches (token_hash, session_hash, fetches, expires_at)
VALUES (sqlc.arg(token_hash)::bytea, sqlc.arg(session_hash)::bytea, 1, sqlc.arg(expires_at)::timestamptz)
ON CONFLICT (token_hash) DO UPDATE SET fetches = playback_key_fetches.fetches + 1
WHERE playback_key_fetches.fetches < sqlc.arg(max_fetches)::integer
RETURNING fetches;

-- name: ReleasePlaybackKeyFetch :exec
-- Gives back a fetch taken by ReservePlaybackKeyFetch for a request that got no key.
UPDATE playback_key_fetches SET fetches = GREATEST(fetches - 1, 0) WHERE token_hash = sqlc.arg(token_hash)::bytea;

-- name: RecordKeyReplay :execrows
-- Marks the token as over its bound and records one key_replay event, only for the request that
-- sets the mark: every later rejected request finds it set and records nothing.
WITH marked AS (
    UPDATE playback_key_fetches SET exceeded_at = sqlc.arg(now)::timestamptz
    WHERE token_hash = sqlc.arg(token_hash)::bytea AND exceeded_at IS NULL
    RETURNING session_hash
)
INSERT INTO playback_events (tenant_id, session_hash, asset_id, kind, at, detail)
SELECT sqlc.arg(tenant_id)::uuid, session_hash, sqlc.arg(asset_id)::uuid, 'key_replay', sqlc.arg(now)::timestamptz,
       jsonb_build_object('limit', sqlc.arg(max_fetches)::integer)
FROM marked;

-- name: InsertPlaybackEvent :exec
INSERT INTO playback_events (tenant_id, session_hash, asset_id, kind, at, detail)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(session_hash)::bytea, sqlc.arg(asset_id)::uuid,
        sqlc.arg(kind)::text, sqlc.arg(at)::timestamptz, sqlc.arg(detail)::jsonb);

-- name: SweepPlaybackKeyFetches :execrows
DELETE FROM playback_key_fetches WHERE expires_at < sqlc.arg(before)::timestamptz;

-- name: HeartbeatPlaybackSession :one
-- Records a heartbeat in one statement, only for a usable session: active, before its expiry, not
-- idle (judged on the PREVIOUS heartbeat), and whose previous heartbeat is at least min_gap old,
-- which is the guard against a script minting tokens in a tight loop. No row means the caller has
-- to find out which of those failed (GetPlaybackSession).
UPDATE playback_sessions SET last_heartbeat_at = sqlc.arg(now)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id_hash = sqlc.arg(id_hash)::bytea
  AND asset_id = sqlc.arg(asset_id)::uuid
  AND state = 'active'
  AND expires_at > sqlc.arg(now)::timestamptz
  AND last_heartbeat_at > sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(idle_seconds)::integer)
  AND last_heartbeat_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(min_gap_seconds)::integer)
RETURNING *;

-- name: EndPlaybackSession :execrows
-- The player's explicit end. Only an active session changes: ended and revoked stay as they are.
UPDATE playback_sessions SET state = 'ended', ended_at = sqlc.arg(now)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id_hash = sqlc.arg(id_hash)::bytea AND state = 'active';

-- name: RevokePlaybackSession :one
-- Revokes one active session of the tenant. No row means unknown, already revoked or already ended.
UPDATE playback_sessions SET state = 'revoked', revoked_at = sqlc.arg(now)::timestamptz,
    revoke_reason = sqlc.narg(reason)::text
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id_hash = sqlc.arg(id_hash)::bytea AND state = 'active'
RETURNING *;

-- name: RevokePlaybackSessionsByFilter :execrows
-- Revokes every active session of the tenant that matches the viewer and/or the asset. The caller
-- guarantees at least one filter is set.
UPDATE playback_sessions SET state = 'revoked', revoked_at = sqlc.arg(now)::timestamptz,
    revoke_reason = sqlc.narg(reason)::text
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND state = 'active'
  AND (sqlc.narg(viewer_id)::text IS NULL OR viewer_id = sqlc.narg(viewer_id)::text)
  AND (sqlc.narg(asset_id)::uuid IS NULL OR asset_id = sqlc.narg(asset_id)::uuid);

-- name: EndExpiredPlaybackSessions :execrows
-- The sweep: ends one bounded batch of active sessions that are past their expiry or idle past
-- their tenant's idle timeout (default_idle_seconds for a tenant without stored settings). The
-- inner filter uses the partial indexes (min_idle_seconds is the smallest idle timeout a tenant
-- can set); the join then applies the tenant's exact value. SKIP LOCKED lets replicas sweep side by
-- side without waiting for each other.
WITH due AS (
    SELECT s.id_hash
    FROM playback_sessions s
    LEFT JOIN playback_settings ps ON ps.tenant_id = s.tenant_id
    WHERE s.state = 'active'
      AND (s.expires_at <= sqlc.arg(now)::timestamptz
           OR s.last_heartbeat_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(min_idle_seconds)::integer))
      AND (s.expires_at <= sqlc.arg(now)::timestamptz
           OR s.last_heartbeat_at <= sqlc.arg(now)::timestamptz
              - make_interval(secs => COALESCE(ps.idle_timeout_seconds, sqlc.arg(default_idle_seconds)::integer)))
    LIMIT sqlc.arg(batch)::integer
    FOR UPDATE OF s SKIP LOCKED
)
UPDATE playback_sessions p SET state = 'ended', ended_at = sqlc.arg(now)::timestamptz
FROM due WHERE p.id_hash = due.id_hash;
