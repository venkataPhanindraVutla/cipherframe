-- name: InsertAuditEvent :one
INSERT INTO audit_events (id, tenant_id, client_id, api_key_id, action, target, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListAuditEventsByTenant :many
-- Oldest first, keyset-paginated: pass the last (created_at, id) seen as the cursor.
SELECT * FROM audit_events
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND (
      sqlc.narg(after_id)::uuid IS NULL
      OR (created_at, id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid)
  )
ORDER BY created_at, id
LIMIT sqlc.arg(max_rows)::integer;
