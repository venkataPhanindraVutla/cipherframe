-- name: InsertAssetDeletionRecord :exec
-- A plain INSERT: the purge writes the record once, in the transaction that ends in the tombstone.
INSERT INTO asset_deletion_records (
    asset_id, tenant_id, reason, requested_at, completed_at, key_id, payload_sha256, envelope
) VALUES (
    sqlc.arg(asset_id)::uuid, sqlc.arg(tenant_id)::uuid, sqlc.arg(reason)::text,
    sqlc.arg(requested_at)::timestamptz, sqlc.arg(completed_at)::timestamptz, sqlc.arg(key_id)::text,
    sqlc.arg(payload_sha256)::bytea, sqlc.arg(envelope)::jsonb
);

-- name: GetAssetDeletionRecord :one
-- Tenant-scoped: another tenant's record is no row.
SELECT * FROM asset_deletion_records WHERE tenant_id = $1 AND asset_id = $2;
