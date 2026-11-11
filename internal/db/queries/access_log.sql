-- The batch insert of playback_access_log is hand-written in repos_access_log.go: sqlc cannot parse
-- a multi-argument unnest.

-- name: ListAssetAccessLog :many
-- Newest first, keyset-paginated on (at, id). cursor_at is 'infinity' and cursor_id the largest
-- bigint for the first page. The session fingerprint is the first 8 hex characters of
-- SHA-256(session_hash || tenant_id bytes): stable for one session, useless on its own. A NULL ip
-- and a NULL fingerprint (no session) come back as the empty string.
SELECT id, asset_id, viewer_id, auth_method, event, at, segments_served, COALESCE(host(ip), '')::text AS ip, user_agent, request_id,
       COALESCE(substr(encode(sha256(session_hash || uuid_send(tenant_id)), 'hex'), 1, 8), '')::text AS session_fingerprint
FROM playback_access_log
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND asset_id = sqlc.arg(asset_id)::uuid
  AND at >= sqlc.arg(from_at)::timestamptz
  AND at < sqlc.arg(to_at)::timestamptz
  AND (sqlc.narg(event)::text IS NULL OR event = sqlc.narg(event)::text)
  AND (at, id) < (sqlc.arg(cursor_at)::timestamptz, sqlc.arg(cursor_id)::bigint)
ORDER BY at DESC, id DESC
LIMIT sqlc.arg(max_rows)::integer;

-- name: ListSessionAccessLog :many
-- The same, for one session (by the hash of its ID).
SELECT id, asset_id, viewer_id, auth_method, event, at, segments_served, COALESCE(host(ip), '')::text AS ip, user_agent, request_id,
       COALESCE(substr(encode(sha256(session_hash || uuid_send(tenant_id)), 'hex'), 1, 8), '')::text AS session_fingerprint
FROM playback_access_log
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND session_hash = sqlc.arg(session_hash)::bytea
  AND at >= sqlc.arg(from_at)::timestamptz
  AND at < sqlc.arg(to_at)::timestamptz
  AND (sqlc.narg(event)::text IS NULL OR event = sqlc.narg(event)::text)
  AND (at, id) < (sqlc.arg(cursor_at)::timestamptz, sqlc.arg(cursor_id)::bigint)
ORDER BY at DESC, id DESC
LIMIT sqlc.arg(max_rows)::integer;

-- name: EnsureAccessLogPartition :one
SELECT playback_access_log_ensure_partition(sqlc.arg(month)::date)::boolean;

-- name: DropAccessLogPartitionsBefore :many
-- Not called by the service yet (retention is M6-4); see the function's comment.
SELECT playback_access_log_drop_partitions_before(sqlc.arg(before)::date)::text;

-- name: SessionViewers :many
-- The viewer and authorization method of sessions, by hash: the access-log writer fills them into
-- events that only know the session.
SELECT id_hash, viewer_id, auth_method FROM playback_sessions WHERE id_hash = ANY(sqlc.arg(hashes)::bytea[]);

-- name: GetPrivacySettings :one
SELECT * FROM privacy_settings WHERE tenant_id = $1;

-- name: UpsertPrivacySettings :one
INSERT INTO privacy_settings (tenant_id, store_ip, store_user_agent, updated_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(store_ip)::boolean, sqlc.arg(store_user_agent)::boolean, sqlc.arg(at)::timestamptz)
ON CONFLICT (tenant_id) DO UPDATE SET
    store_ip = EXCLUDED.store_ip, store_user_agent = EXCLUDED.store_user_agent, updated_at = EXCLUDED.updated_at
RETURNING *;
