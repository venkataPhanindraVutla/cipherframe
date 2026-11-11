-- +goose Up
-- M4-8: JWT and signed-callback authorization of playback sessions (ADR 0029, 0031).
--
-- A session can now be started by a viewer's browser through a JWT or a signed callback instead of
-- by the embedding application's API key, so a session has no client in those cases. auth_method
-- records how the session was authorised, and the CHECK ties it to client_id: an API-key session
-- always has the client that made it, and the other two never do.
ALTER TABLE playback_sessions
    ALTER COLUMN client_id DROP NOT NULL,
    ADD COLUMN auth_method text NOT NULL DEFAULT 'api_key'
        CONSTRAINT playback_sessions_auth_method_allowed CHECK (auth_method IN ('api_key', 'jwt', 'callback')),
    ADD CONSTRAINT playback_sessions_client_iff_api_key CHECK ((client_id IS NOT NULL) = (auth_method = 'api_key'));

-- One optional row per tenant: how the tenant authorises browser-started sessions. A tenant without
-- a row has both methods off (db.DefaultPlaybackAuth).
--
-- The callback secret is never stored in the clear. callback_secret_envelope is the secret wrapped
-- by the key provider (ADR 0019, 0020): a small binary envelope that records the provider, the KEK
-- id and version and the ciphertext, with associated data that binds it to the tenant, its purpose
-- and callback_secret_version. A rotation keeps the previous secret (wrapped the same way, under
-- its own version) so edge can sign with both for 24 hours (ADR 0016's overlap idea; Standard
-- Webhooks allows several signatures).
CREATE TABLE playback_auth (
    tenant_id                         uuid PRIMARY KEY REFERENCES tenants (id),
    jwt_enabled                       boolean NOT NULL DEFAULT false,
    jwt_issuer                        text NOT NULL DEFAULT ''
        CONSTRAINT playback_auth_issuer_len CHECK (char_length(jwt_issuer) <= 512),
    jwt_audiences                     text[] NOT NULL DEFAULT '{}'
        CONSTRAINT playback_auth_audiences_max CHECK (cardinality(jwt_audiences) <= 10),
    jwt_jwks_url                      text
        CONSTRAINT playback_auth_jwks_url CHECK (jwt_jwks_url IS NULL
            OR (jwt_jwks_url ~ '^https://' AND char_length(jwt_jwks_url) <= 2048)),
    jwt_viewer_claim                  text NOT NULL DEFAULT 'sub'
        CONSTRAINT playback_auth_viewer_claim_len CHECK (char_length(jwt_viewer_claim) BETWEEN 1 AND 64),
    callback_enabled                  boolean NOT NULL DEFAULT false,
    callback_url                      text
        CONSTRAINT playback_auth_callback_url CHECK (callback_url IS NULL
            OR (callback_url ~ '^https://' AND char_length(callback_url) <= 2048)),
    callback_secret_envelope          bytea,
    callback_secret_version           integer NOT NULL DEFAULT 0,
    callback_secret_prev_envelope     bytea,
    callback_secret_prev_version      integer,
    callback_secret_rotated_at        timestamptz,
    updated_at                        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT playback_auth_secret_version CHECK (
        (callback_secret_envelope IS NULL) = (callback_secret_version = 0)
    ),
    CONSTRAINT playback_auth_prev_secret CHECK (
        (callback_secret_prev_envelope IS NULL) = (callback_secret_prev_version IS NULL)
    ),
    CONSTRAINT playback_auth_callback_needs_url CHECK (NOT callback_enabled OR callback_url IS NOT NULL)
);

-- Public JWKs a tenant uploaded for verifying its JWTs. A row is a public key only: the API refuses
-- private JWKs. At most 20 per tenant: the repository counts and inserts under a per-tenant
-- advisory lock, because a CHECK constraint cannot count rows.
CREATE TABLE playback_jwt_keys (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    kid        text NOT NULL CONSTRAINT playback_jwt_keys_kid_len CHECK (char_length(kid) BETWEEN 1 AND 128),
    alg        text NOT NULL CONSTRAINT playback_jwt_keys_alg_allowed CHECK (alg IN ('EdDSA', 'ES256', 'RS256')),
    jwk        jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kid)
);

-- Single-use JWT ids. jti_hash is the SHA-256 of the token's jti, so a reader of this table learns
-- nothing about the identifiers the tenant picks. expires_at is the token's expiry plus the clock
-- skew allowance: a replay after it fails on the token's own exp, so the row is dead weight and the
-- playback sweeper deletes it.
CREATE TABLE playback_jwt_jti (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    jti_hash   bytea NOT NULL CONSTRAINT playback_jwt_jti_hash_len CHECK (octet_length(jti_hash) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, jti_hash)
);

CREATE INDEX playback_jwt_jti_expires_idx ON playback_jwt_jti (expires_at);

-- +goose Down
DROP TABLE playback_jwt_jti;
DROP TABLE playback_jwt_keys;
DROP TABLE playback_auth;
ALTER TABLE playback_sessions
    DROP CONSTRAINT playback_sessions_client_iff_api_key,
    DROP COLUMN auth_method;
ALTER TABLE playback_sessions ALTER COLUMN client_id SET NOT NULL;
