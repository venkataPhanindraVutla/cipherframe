-- +goose Up
-- Playback settings and sessions (ADR 0028, 0030, M4-1).
--
-- playback_settings holds one optional row per tenant. A tenant without a row uses the defaults,
-- which are the column defaults below (and db.DefaultPlaybackSettings, kept equal by a test). All
-- columns are NOT NULL, and the CHECK constraints are the backstop for the validation the API does
-- first.

CREATE TABLE playback_settings (
    tenant_id                  uuid PRIMARY KEY REFERENCES tenants (id),
    token_ttl_seconds          integer NOT NULL DEFAULT 600
        CONSTRAINT playback_settings_token_ttl_range CHECK (token_ttl_seconds BETWEEN 60 AND 3600),
    heartbeat_interval_seconds integer NOT NULL DEFAULT 60
        CONSTRAINT playback_settings_heartbeat_range CHECK (heartbeat_interval_seconds BETWEEN 10 AND 600),
    idle_timeout_seconds       integer NOT NULL DEFAULT 300
        CONSTRAINT playback_settings_idle_range CHECK (idle_timeout_seconds BETWEEN 30 AND 3600),
    session_max_seconds        integer NOT NULL DEFAULT 14400
        CONSTRAINT playback_settings_session_max_range CHECK (session_max_seconds BETWEEN 300 AND 86400),
    -- 0 means unlimited.
    max_sessions_per_viewer    integer NOT NULL DEFAULT 3
        CONSTRAINT playback_settings_max_sessions_range CHECK (max_sessions_per_viewer BETWEEN 0 AND 100),
    key_fetches_per_token      integer NOT NULL DEFAULT 20
        CONSTRAINT playback_settings_key_fetches_range CHECK (key_fetches_per_token BETWEEN 1 AND 1000),
    key_requests_per_minute    integer NOT NULL DEFAULT 30
        CONSTRAINT playback_settings_key_rpm_range CHECK (key_requests_per_minute BETWEEN 1 AND 600),
    allowed_origins            text[] NOT NULL DEFAULT '{}'
        CONSTRAINT playback_settings_origins_max CHECK (cardinality(allowed_origins) <= 20),
    token_in_url               boolean NOT NULL DEFAULT false,
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    -- A token must outlive at least one heartbeat, and a session must survive at least one
    -- heartbeat without being idle.
    CONSTRAINT playback_settings_heartbeat_below_ttl CHECK (heartbeat_interval_seconds < token_ttl_seconds),
    CONSTRAINT playback_settings_heartbeat_below_idle CHECK (heartbeat_interval_seconds < idle_timeout_seconds)
);

-- A session ID is a capability: whoever holds it can use it (internal/id/session.go). The primary
-- key is therefore the SHA-256 of its text form ("ses_..."), never the ID itself. A reader of this
-- table (a backup, a replica, a SQL injection that reaches SELECT) cannot replay a session, and
-- edge finds a row by hashing the ID in the request path. The ID is 256 random bits, so a fast
-- hash is enough (the same reasoning as upload_tokens.token_hash).
--
-- viewer_id is the embedding application's pseudonymous identifier for the viewer (1 to 128
-- characters). Operators should not use an email address or other direct identifier.
-- expires_at is created_at plus the tenant's session_max_seconds at creation time.
CREATE TABLE playback_sessions (
    id_hash           bytea PRIMARY KEY
        CONSTRAINT playback_sessions_hash_len CHECK (octet_length(id_hash) = 32),
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    client_id         uuid NOT NULL REFERENCES clients (id),
    asset_id          uuid NOT NULL REFERENCES assets (id),
    viewer_id         text NOT NULL
        CONSTRAINT playback_sessions_viewer_len CHECK (char_length(viewer_id) BETWEEN 1 AND 128),
    state             text NOT NULL DEFAULT 'active'
        CONSTRAINT playback_sessions_state_allowed CHECK (state IN ('active', 'revoked', 'ended')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    ended_at          timestamptz,
    revoked_at        timestamptz,
    revoke_reason     text
        CONSTRAINT playback_sessions_reason_len CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 200),
    CONSTRAINT playback_sessions_expiry_after_create CHECK (expires_at > created_at),
    CONSTRAINT playback_sessions_state_times CHECK (
        (state = 'active' AND ended_at IS NULL AND revoked_at IS NULL)
        OR (state = 'ended' AND ended_at IS NOT NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL)
    )
);

-- "Count the active sessions of one viewer": the only hot query, on every session creation.
CREATE INDEX playback_sessions_viewer_active_idx ON playback_sessions (tenant_id, viewer_id)
    WHERE state = 'active';

-- Revoking or deleting by asset, and the foreign key.
CREATE INDEX playback_sessions_asset_idx ON playback_sessions (asset_id);

-- +goose Down
DROP TABLE playback_sessions;
DROP TABLE playback_settings;
