-- name: InsertAssetSubtitle :one
INSERT INTO asset_subtitles (id, asset_id, tenant_id, language, label, is_default, origin, cue_count, duration_ms, size_bytes, sha256, created_at)
VALUES (
    sqlc.arg(id)::uuid, sqlc.arg(asset_id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(language)::text,
    sqlc.arg(label)::text, sqlc.arg(is_default)::boolean, sqlc.arg(origin)::text, sqlc.arg(cue_count)::integer,
    sqlc.arg(duration_ms)::bigint, sqlc.arg(size_bytes)::bigint, sqlc.arg(sha256)::bytea, sqlc.arg(created_at)::timestamptz
)
RETURNING *;

-- name: ListAssetSubtitles :many
SELECT * FROM asset_subtitles
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND asset_id = sqlc.arg(asset_id)::uuid
ORDER BY created_at, id;

-- name: GetAssetSubtitle :one
SELECT * FROM asset_subtitles
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND asset_id = sqlc.arg(asset_id)::uuid AND id = sqlc.arg(id)::uuid;

-- name: DeleteAssetSubtitle :execrows
DELETE FROM asset_subtitles
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND asset_id = sqlc.arg(asset_id)::uuid AND id = sqlc.arg(id)::uuid;

-- name: ClearAssetSubtitleDefault :exec
UPDATE asset_subtitles SET is_default = false WHERE asset_id = sqlc.arg(asset_id)::uuid AND is_default;

-- name: DeleteAssetSubtitles :execrows
-- Every track row of the asset (the purge: the objects are gone, so is the metadata).
DELETE FROM asset_subtitles WHERE asset_id = $1;

-- name: DeleteAssetArtifactByKey :execrows
DELETE FROM asset_artifacts WHERE asset_id = sqlc.arg(asset_id)::uuid AND bucket = sqlc.arg(bucket)::text AND object_key = sqlc.arg(object_key)::text;
