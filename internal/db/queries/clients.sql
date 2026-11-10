-- name: CreateClient :one
INSERT INTO clients (id, tenant_id, name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetClient :one
SELECT * FROM clients
WHERE tenant_id = $1 AND id = $2;

-- name: ListClientsByTenant :many
SELECT * FROM clients
WHERE tenant_id = $1
ORDER BY created_at, id
LIMIT $2 OFFSET $3;

-- name: ListClientsPage :many
-- Keyset pagination on the UUIDv7 id, which is creation-ordered. Pass a NULL after_id for the first page.
SELECT * FROM clients
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::integer;
