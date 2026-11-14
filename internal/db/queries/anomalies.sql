-- Anomaly events (M4-9). Detection code is in package anomaly; see migration 00012.

-- name: LockAnomalySubject :exec
-- Serialises raising one kind for one subject (a session or a viewer) until the transaction ends,
-- so two replicas that detect the same thing at once record one event.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: InsertSessionAnomaly :execrows
-- Records an event of a session unless one of the same kind exists for it at or after since. The
-- viewer is copied from the session row. Returns 1 when it inserted.
INSERT INTO playback_events (tenant_id, session_hash, viewer_id, asset_id, kind, at, detail)
SELECT sqlc.arg(tenant_id)::uuid, sqlc.arg(session_hash)::bytea,
       (SELECT s.viewer_id FROM playback_sessions s WHERE s.id_hash = sqlc.arg(session_hash)::bytea),
       sqlc.arg(asset_id)::uuid, sqlc.arg(kind)::text, sqlc.arg(at)::timestamptz, sqlc.arg(detail)::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM playback_events e
    WHERE e.session_hash = sqlc.arg(session_hash)::bytea AND e.kind = sqlc.arg(kind)::text
      AND e.at >= sqlc.arg(since)::timestamptz);

-- name: InsertViewerAnomaly :execrows
-- The same for a viewer-level event (no session): one per tenant, viewer and kind since the time.
INSERT INTO playback_events (tenant_id, session_hash, viewer_id, asset_id, kind, at, detail)
SELECT sqlc.arg(tenant_id)::uuid, NULL, sqlc.arg(viewer_id)::text,
       sqlc.arg(asset_id)::uuid, sqlc.arg(kind)::text, sqlc.arg(at)::timestamptz, sqlc.arg(detail)::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM playback_events e
    WHERE e.tenant_id = sqlc.arg(tenant_id)::uuid AND e.viewer_id = sqlc.arg(viewer_id)::text
      AND e.session_hash IS NULL AND e.kind = sqlc.arg(kind)::text
      AND e.at >= sqlc.arg(since)::timestamptz);

-- name: CountViewerSessionsCreatedSince :one
-- Sessions created for one viewer in the window: the rapid_session_creation signal.
SELECT count(*) FROM playback_sessions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND viewer_id = sqlc.arg(viewer_id)::text
  AND created_at > sqlc.arg(since)::timestamptz;

-- name: ListPlaybackEvents :many
-- Newest first, keyset-paginated on (at, id); cursor_at is the exclusive upper bound of at and
-- cursor_id the largest uuid for the first page. The session fingerprint is the same as the access
-- log's: the first 8 hex characters of SHA-256(session_hash || tenant_id bytes).
SELECT id, kind, at, asset_id, viewer_id, detail,
       COALESCE(substr(encode(sha256(session_hash || uuid_send(tenant_id)), 'hex'), 1, 8), '')::text AS session_fingerprint
FROM playback_events
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(asset_id)::uuid IS NULL OR asset_id = sqlc.narg(asset_id)::uuid)
  AND (sqlc.narg(viewer_id)::text IS NULL OR viewer_id = sqlc.narg(viewer_id)::text)
  AND at >= sqlc.arg(from_at)::timestamptz
  AND at < sqlc.arg(to_at)::timestamptz
  AND (at, id) < (sqlc.arg(cursor_at)::timestamptz, sqlc.arg(cursor_id)::uuid)
ORDER BY at DESC, id DESC
LIMIT sqlc.arg(max_rows)::integer;

-- name: DeletePlaybackEventsBefore :execrows
-- Retention (M6-4): one bounded batch of anomaly events older than the cutoff.
DELETE FROM playback_events
WHERE id IN (
    SELECT e.id FROM playback_events e WHERE e.at < sqlc.arg(cutoff)::timestamptz ORDER BY e.at LIMIT sqlc.arg(batch)::integer
);
