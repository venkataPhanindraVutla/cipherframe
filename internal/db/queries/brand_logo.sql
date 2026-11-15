-- name: LockBrand :exec
-- Serialises the brand logo's writers, the garbage collection of old versions and the pinning of an
-- asset until the transaction ends, so a version an asset is about to pin is never removed.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 2));

-- name: InsertLogoVersion :one
INSERT INTO tenant_logo_versions (id, tenant_id, sha256, size_bytes, width, height, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetTenantLogo :one
SELECT l.tenant_id, l.version_id, l.corner, l.opacity_percent, l.enabled, l.updated_at,
       v.sha256, v.size_bytes, v.width, v.height, v.created_at AS version_created_at
FROM tenant_logos l
JOIN tenant_logo_versions v ON v.id = l.version_id
WHERE l.tenant_id = $1;

-- name: UpsertTenantLogo :exec
INSERT INTO tenant_logos (tenant_id, version_id, corner, opacity_percent, enabled, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id) DO UPDATE SET
    version_id = EXCLUDED.version_id,
    corner = EXCLUDED.corner,
    opacity_percent = EXCLUDED.opacity_percent,
    enabled = EXCLUDED.enabled,
    updated_at = EXCLUDED.updated_at;

-- name: UpdateTenantLogoPlacement :execrows
UPDATE tenant_logos SET corner = $2, opacity_percent = $3, enabled = $4, updated_at = $5
WHERE tenant_id = $1;

-- name: DeleteTenantLogo :execrows
DELETE FROM tenant_logos WHERE tenant_id = $1;

-- name: ListUnusedLogoVersions :many
-- Versions that may be removed: not the tenant's current one, and not the version of an asset whose
-- processing or masking has yet to finish (it must still use it, also on a retry).
SELECT v.id FROM tenant_logo_versions v
WHERE v.tenant_id = $1
  AND NOT EXISTS (SELECT 1 FROM tenant_logos l WHERE l.version_id = v.id)
  AND NOT EXISTS (
        SELECT 1 FROM asset_logo_pins p
        JOIN assets a ON a.id = p.asset_id
        WHERE p.version_id = v.id
          AND (a.state IN ('committed', 'processing') OR a.masking_state = 'pending'))
ORDER BY v.id;

-- name: DeleteLogoVersion :execrows
DELETE FROM tenant_logo_versions WHERE tenant_id = $1 AND id = $2;

-- name: PinAssetLogo :exec
-- Records what the asset is transcoded with, once: the tenant's current logo while it is enabled,
-- otherwise no logo. A later call changes nothing.
INSERT INTO asset_logo_pins (asset_id, tenant_id, version_id, sha256, corner, opacity_percent, pinned_at)
SELECT a.id, a.tenant_id,
       (SELECT l.version_id FROM tenant_logos l WHERE l.tenant_id = a.tenant_id AND l.enabled),
       (SELECT v.sha256 FROM tenant_logos l JOIN tenant_logo_versions v ON v.id = l.version_id WHERE l.tenant_id = a.tenant_id AND l.enabled),
       (SELECT l.corner FROM tenant_logos l WHERE l.tenant_id = a.tenant_id AND l.enabled),
       (SELECT l.opacity_percent FROM tenant_logos l WHERE l.tenant_id = a.tenant_id AND l.enabled),
       sqlc.arg(at)::timestamptz
FROM assets a
WHERE a.tenant_id = sqlc.arg(tenant_id)::uuid AND a.id = sqlc.arg(asset_id)::uuid
ON CONFLICT (asset_id) DO NOTHING;

-- name: GetAssetLogoPin :one
SELECT * FROM asset_logo_pins WHERE tenant_id = $1 AND asset_id = $2;
