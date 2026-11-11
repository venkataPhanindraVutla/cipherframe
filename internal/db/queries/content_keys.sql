-- name: InsertContentKey :one
-- The asset must belong to the tenant; otherwise no row is inserted (not_found). A second key for
-- the same asset violates content_keys_asset_id_key (conflict): there is one key per asset (I7).
INSERT INTO content_keys (id, asset_id, provider, kek_key_id, kek_version, envelope_version, wrapped)
SELECT sqlc.arg(id)::uuid, a.id, sqlc.arg(provider)::text, sqlc.arg(kek_key_id)::text,
       sqlc.arg(kek_version)::text, sqlc.arg(envelope_version)::smallint, sqlc.arg(wrapped)::bytea
FROM assets a
WHERE a.id = sqlc.arg(asset_id)::uuid AND a.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING *;

-- name: GetContentKeyByAsset :one
-- Tenant-scoped lookup through the asset.
SELECT k.* FROM content_keys k
JOIN assets a ON a.id = k.asset_id
WHERE a.tenant_id = sqlc.arg(tenant_id)::uuid AND k.asset_id = sqlc.arg(asset_id)::uuid;

-- name: DeleteContentKeyByAsset :execrows
-- Crypto-shredding: the row is destroyed, not flagged. Returns the number of rows deleted.
DELETE FROM content_keys k
USING assets a
WHERE a.id = k.asset_id
  AND a.tenant_id = sqlc.arg(tenant_id)::uuid
  AND k.asset_id = sqlc.arg(asset_id)::uuid;

-- name: ListContentKeysForRewrap :many
-- Keyset pagination on the UUIDv7 id. Pass a NULL after_id for the first page.
SELECT * FROM content_keys
WHERE provider = sqlc.arg(provider)::text
  AND kek_key_id = sqlc.arg(kek_key_id)::text
  AND kek_version = sqlc.arg(kek_version)::text
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::integer;

-- name: UpdateContentKeyWrapped :execrows
-- Re-wrap. Applies only while the row still names the KEK the caller read, so two concurrent
-- re-wraps cannot overwrite each other with stale data.
UPDATE content_keys
SET provider         = sqlc.arg(provider)::text,
    kek_key_id       = sqlc.arg(kek_key_id)::text,
    kek_version      = sqlc.arg(kek_version)::text,
    envelope_version = sqlc.arg(envelope_version)::smallint,
    wrapped          = sqlc.arg(wrapped)::bytea,
    rewrapped_at     = now()
WHERE id = sqlc.arg(id)::uuid
  AND provider    = sqlc.arg(old_provider)::text
  AND kek_key_id  = sqlc.arg(old_kek_key_id)::text
  AND kek_version = sqlc.arg(old_kek_version)::text;
