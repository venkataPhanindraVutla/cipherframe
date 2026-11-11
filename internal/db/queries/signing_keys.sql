-- name: LockSigningKeys :exec
-- Serialises every change of the signing key set until the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: ListSigningKeys :many
-- The published key set: every key, oldest first. The wrapped private key is not selected.
SELECT key_id, purpose, algorithm, public_key, state, is_current, created_at, activated_at, retired_at
FROM signing_keys
WHERE purpose = sqlc.arg(purpose)::text
ORDER BY created_at, key_id;

-- name: GetCurrentSigningKey :one
SELECT * FROM signing_keys
WHERE purpose = sqlc.arg(purpose)::text AND state = 'active' AND is_current;

-- name: GetSigningKey :one
SELECT * FROM signing_keys WHERE key_id = sqlc.arg(key_id)::text;

-- name: CountSigningKeys :one
SELECT count(*) FROM signing_keys WHERE purpose = sqlc.arg(purpose)::text;

-- name: ClearCurrentSigningKey :exec
-- Demotes the current signer to a plain active key. It stays published and still verifies.
UPDATE signing_keys SET is_current = false
WHERE purpose = sqlc.arg(purpose)::text AND is_current;

-- name: InsertSigningKey :one
INSERT INTO signing_keys (key_id, purpose, algorithm, public_key, private_envelope, state, is_current, created_at, activated_at)
VALUES (sqlc.arg(key_id)::text, sqlc.arg(purpose)::text, sqlc.arg(algorithm)::text, sqlc.arg(public_key)::bytea,
        sqlc.arg(private_envelope)::bytea, 'active', true, sqlc.arg(at)::timestamptz, sqlc.arg(at)::timestamptz)
RETURNING *;

-- name: RetireSigningKey :one
-- Only a non-current active key is retired; the caller has already checked both under the lock.
UPDATE signing_keys SET state = 'retired', retired_at = sqlc.arg(at)::timestamptz
WHERE key_id = sqlc.arg(key_id)::text AND state = 'active' AND NOT is_current
RETURNING *;
