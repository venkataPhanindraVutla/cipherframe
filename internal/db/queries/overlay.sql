-- name: GetOverlaySettings :one
SELECT * FROM overlay_settings WHERE tenant_id = $1;

-- name: UpsertOverlaySettings :one
INSERT INTO overlay_settings (tenant_id, enabled, template, opacity, font_size_fraction, color, updated_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(enabled)::boolean, sqlc.arg(template)::text, sqlc.arg(opacity)::double precision,
        sqlc.arg(font_size_fraction)::double precision, sqlc.arg(color)::text, sqlc.arg(at)::timestamptz)
ON CONFLICT (tenant_id) DO UPDATE SET
    enabled = EXCLUDED.enabled, template = EXCLUDED.template, opacity = EXCLUDED.opacity,
    font_size_fraction = EXCLUDED.font_size_fraction, color = EXCLUDED.color, updated_at = EXCLUDED.updated_at
RETURNING *;

-- name: FindSessionsByOverlayCode :many
-- A leaked overlay code back to its sessions. A code is 40 bits, so more than one session can match;
-- the fingerprint is the access trail's (first 8 hex characters of SHA-256(session_hash || tenant_id)).
SELECT asset_id, viewer_id, auth_method, state, created_at,
       substr(encode(sha256(id_hash || uuid_send(tenant_id)), 'hex'), 1, 8)::text AS session_fingerprint
FROM playback_sessions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND overlay_code = sqlc.arg(code)::text
ORDER BY created_at DESC
LIMIT 20;

-- name: ClearOverlayCodesBefore :execrows
-- Retention: sessions created before the cutoff stop being traceable from a code.
UPDATE playback_sessions SET overlay_code = NULL
WHERE id_hash IN (
    SELECT id_hash FROM playback_sessions
    WHERE overlay_code IS NOT NULL AND created_at < sqlc.arg(cutoff)::timestamptz
    LIMIT sqlc.arg(batch)::integer
);
