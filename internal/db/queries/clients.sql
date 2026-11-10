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
