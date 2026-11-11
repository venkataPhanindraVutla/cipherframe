-- name: InsertAssetManifest :exec
-- A plain INSERT: a retry deletes the previous manifest first, so a duplicate is a bug.
INSERT INTO asset_manifests (asset_id, tenant_id, key_id, payload_sha256, top_root, envelope, created_at)
VALUES (
    sqlc.arg(asset_id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(key_id)::text,
    sqlc.arg(payload_sha256)::bytea, sqlc.arg(top_root)::bytea, sqlc.arg(envelope)::jsonb,
    sqlc.arg(created_at)::timestamptz
);

-- name: GetAssetManifest :one
SELECT * FROM asset_manifests WHERE asset_id = $1;

-- name: DeleteAssetManifest :execrows
DELETE FROM asset_manifests WHERE asset_id = $1;
