-- name: GetPlaybackAuth :one
SELECT * FROM playback_auth WHERE tenant_id = $1;

-- name: UpsertPlaybackAuthConfig :one
-- Replaces the configuration columns only. The callback secret columns are untouched: only a
-- rotation changes them.
INSERT INTO playback_auth (
    tenant_id, jwt_enabled, jwt_issuer, jwt_audiences, jwt_jwks_url, jwt_viewer_claim,
    callback_enabled, callback_url, updated_at
) VALUES (
    sqlc.arg(tenant_id)::uuid, sqlc.arg(jwt_enabled)::boolean, sqlc.arg(jwt_issuer)::text,
    sqlc.arg(jwt_audiences)::text[], sqlc.narg(jwt_jwks_url)::text, sqlc.arg(jwt_viewer_claim)::text,
    sqlc.arg(callback_enabled)::boolean, sqlc.narg(callback_url)::text, sqlc.arg(at)::timestamptz
)
ON CONFLICT (tenant_id) DO UPDATE SET
    jwt_enabled      = EXCLUDED.jwt_enabled,
    jwt_issuer       = EXCLUDED.jwt_issuer,
    jwt_audiences    = EXCLUDED.jwt_audiences,
    jwt_jwks_url     = EXCLUDED.jwt_jwks_url,
    jwt_viewer_claim = EXCLUDED.jwt_viewer_claim,
    callback_enabled = EXCLUDED.callback_enabled,
    callback_url     = EXCLUDED.callback_url,
    updated_at       = EXCLUDED.updated_at
RETURNING *;

-- name: RotatePlaybackCallbackSecret :one
-- Stores a new current secret and moves the old current one to "previous". The new version is
-- always the old one plus one, computed here so two racing rotations cannot pick the same number:
-- the caller passes the version it wrapped for, and no row is updated when it is no longer next.
INSERT INTO playback_auth (tenant_id, callback_secret_envelope, callback_secret_version, callback_secret_rotated_at, updated_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(envelope)::bytea, sqlc.arg(version)::integer, sqlc.arg(at)::timestamptz, sqlc.arg(at)::timestamptz)
ON CONFLICT (tenant_id) DO UPDATE SET
    callback_secret_prev_envelope = playback_auth.callback_secret_envelope,
    callback_secret_prev_version  = CASE WHEN playback_auth.callback_secret_envelope IS NULL THEN NULL
                                         ELSE playback_auth.callback_secret_version END,
    callback_secret_envelope      = EXCLUDED.callback_secret_envelope,
    callback_secret_version       = EXCLUDED.callback_secret_version,
    callback_secret_rotated_at    = EXCLUDED.callback_secret_rotated_at,
    updated_at                    = EXCLUDED.updated_at
WHERE playback_auth.callback_secret_version = EXCLUDED.callback_secret_version - 1
RETURNING *;

-- name: LockPlaybackAuth :exec
-- Serialises the changes of one tenant's authorization configuration until the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: ListPlaybackJWTKeys :many
SELECT * FROM playback_jwt_keys WHERE tenant_id = $1 ORDER BY kid;

-- name: CountPlaybackJWTKeysExcept :one
SELECT count(*) FROM playback_jwt_keys WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND kid <> sqlc.arg(kid)::text;

-- name: UpsertPlaybackJWTKey :one
INSERT INTO playback_jwt_keys (tenant_id, kid, alg, jwk, created_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(kid)::text, sqlc.arg(alg)::text, sqlc.arg(jwk)::jsonb, sqlc.arg(at)::timestamptz)
ON CONFLICT (tenant_id, kid) DO UPDATE SET alg = EXCLUDED.alg, jwk = EXCLUDED.jwk, created_at = EXCLUDED.created_at
RETURNING *;

-- name: DeletePlaybackJWTKey :execrows
DELETE FROM playback_jwt_keys WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND kid = sqlc.arg(kid)::text;

-- name: ClaimPlaybackJWTID :execrows
-- Records a JWT id as used. No row inserted means it was used before: a replay.
INSERT INTO playback_jwt_jti (tenant_id, jti_hash, expires_at)
VALUES (sqlc.arg(tenant_id)::uuid, sqlc.arg(jti_hash)::bytea, sqlc.arg(expires_at)::timestamptz)
ON CONFLICT (tenant_id, jti_hash) DO NOTHING;

-- name: SweepPlaybackJWTIDs :execrows
DELETE FROM playback_jwt_jti WHERE expires_at < sqlc.arg(before)::timestamptz;
