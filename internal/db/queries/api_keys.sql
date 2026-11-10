-- name: CreateAPIKey :one
INSERT INTO api_keys (id, client_id, name, prefix, secret_hash, pepper_version, scopes)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetAPIKey :one
-- Tenant-scoped lookup by key ID (management paths).
SELECT k.* FROM api_keys k
JOIN clients c ON c.id = k.client_id
WHERE c.tenant_id = $1 AND k.id = $2;

-- name: GetActiveAPIKeyByPrefix :one
-- Authentication lookup. Revoked keys are never returned. The tenant and the disabled markers
-- of the owning client and tenant are included so the caller can fail closed.
SELECT
    k.id, k.client_id, k.name, k.prefix, k.secret_hash, k.pepper_version, k.scopes,
    k.previous_secret_hash, k.previous_pepper_version, k.previous_valid_until,
    k.created_at, k.rotated_at, k.revoked_at, k.last_used_at,
    c.tenant_id AS tenant_id,
    c.disabled_at AS client_disabled_at,
    t.disabled_at AS tenant_disabled_at
FROM api_keys k
JOIN clients c ON c.id = k.client_id
JOIN tenants t ON t.id = c.tenant_id
WHERE k.prefix = $1 AND k.revoked_at IS NULL;

-- name: RotateAPIKey :one
-- Replaces the secret on the same row; the previous hash moves to previous_*. Ownership never moves.
UPDATE api_keys AS k
SET previous_secret_hash    = k.secret_hash,
    previous_pepper_version = k.pepper_version,
    previous_valid_until    = sqlc.arg(previous_valid_until)::timestamptz,
    secret_hash             = sqlc.arg(new_secret_hash)::bytea,
    pepper_version          = sqlc.arg(new_pepper_version)::integer,
    rotated_at              = sqlc.arg(rotated_at)::timestamptz
FROM clients c
WHERE k.id = sqlc.arg(id)::uuid
  AND k.revoked_at IS NULL
  AND c.id = k.client_id
  AND c.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING k.*;

-- name: RevokeAPIKey :one
-- Idempotent: an already revoked key keeps its original revoked_at.
UPDATE api_keys AS k
SET revoked_at = COALESCE(k.revoked_at, sqlc.arg(revoked_at)::timestamptz)
FROM clients c
WHERE k.id = sqlc.arg(id)::uuid
  AND c.id = k.client_id
  AND c.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING k.*;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = sqlc.arg(last_used_at)::timestamptz
WHERE id = sqlc.arg(id)::uuid;

-- name: CountAPIKeysByPepperVersion :many
-- Counts non-revoked keys per pepper version: the current hash plus any previous hash that is
-- still within its overlap window at now.
SELECT version::integer AS pepper_version, count(*)::bigint AS key_count
FROM (
    SELECT pepper_version AS version
    FROM api_keys
    WHERE revoked_at IS NULL
    UNION ALL
    SELECT previous_pepper_version AS version
    FROM api_keys
    WHERE revoked_at IS NULL
      AND previous_pepper_version IS NOT NULL
      AND previous_valid_until > sqlc.arg(now)::timestamptz
) AS refs
GROUP BY version
ORDER BY version;
