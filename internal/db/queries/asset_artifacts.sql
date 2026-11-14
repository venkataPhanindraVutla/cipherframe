-- name: UpsertAssetArtifact :exec
-- Registers (or re-registers, on a retry) one derived object. An object key that already belongs
-- to another asset is never taken over (the WHERE clause), which would indicate a key-layout bug.
INSERT INTO asset_artifacts (asset_id, kind, rendition, bucket, object_key, size_bytes, sha256, variant)
VALUES (
    sqlc.arg(asset_id)::uuid, sqlc.arg(kind)::text, sqlc.narg(rendition)::text, sqlc.arg(bucket)::text,
    sqlc.arg(object_key)::text, sqlc.arg(size_bytes)::bigint, sqlc.arg(sha256)::bytea, sqlc.arg(variant)::text
)
ON CONFLICT (bucket, object_key) DO UPDATE
SET kind = EXCLUDED.kind, rendition = EXCLUDED.rendition,
    size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256, created_at = now()
WHERE asset_artifacts.asset_id = EXCLUDED.asset_id;

-- name: ListAssetArtifacts :many
SELECT * FROM asset_artifacts WHERE asset_id = $1 ORDER BY bucket, object_key;

-- name: DeleteAssetHLSArtifacts :execrows
-- The playlists, init segments and media segments of one variant of an asset (everything the
-- processing job, or the masking job for the masked variant, makes again on a retry). A poster is
-- not one of them.
DELETE FROM asset_artifacts
WHERE asset_id = sqlc.arg(asset_id)::uuid AND variant = sqlc.arg(variant)::text
  AND kind IN ('master', 'playlist', 'init', 'segment');

-- name: FindTenantArtifactsBySHA256 :many
-- The HLS objects of the tenant's ready assets whose stored bytes hash to sha256 (the lookup behind
-- a hash-only verify). A hash can repeat across assets (an identical playlist), so several rows
-- are possible; the oldest come first.
SELECT a.asset_id, a.variant, a.object_key
FROM asset_artifacts a
JOIN assets s ON s.id = a.asset_id
WHERE s.tenant_id = sqlc.arg(tenant_id)::uuid AND s.state = 'ready'
  AND a.sha256 = sqlc.arg(sha256)::bytea AND a.bucket = 'delivery'
  AND a.kind IN ('master', 'playlist', 'init', 'segment')
ORDER BY a.created_at, a.object_key
LIMIT 20;
