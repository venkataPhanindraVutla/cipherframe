-- name: CreateTenant :one
INSERT INTO tenants (id, name)
VALUES ($1, $2)
RETURNING *;

-- name: GetTenant :one
SELECT * FROM tenants WHERE id = $1;
