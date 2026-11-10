-- name: CreateAsset :one
-- The client must belong to the tenant; otherwise no row is inserted.
INSERT INTO assets (id, tenant_id, created_by_client_id, state)
SELECT sqlc.arg(id)::uuid, c.tenant_id, c.id, sqlc.arg(state)::text
FROM clients c
WHERE c.id = sqlc.arg(client_id)::uuid AND c.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets
WHERE tenant_id = $1 AND id = $2;
