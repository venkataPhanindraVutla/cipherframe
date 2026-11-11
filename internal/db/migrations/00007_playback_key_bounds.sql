-- +goose Up
-- Key endpoint bounds and anomaly events (ADR 0028, M4-4).
--
-- Both bounds are enforced in Postgres, so they hold across edge replicas and restarts:
--
--  * playback_key_fetches: one row per playback token that has asked for the key, holding how many
--    key responses it has been granted. The token itself is never stored, only the SHA-256 of its
--    exact text. expires_at is the token's own expiry: a row is useless afterwards and a periodic
--    sweep deletes it (SweepKeyFetches). exceeded_at is set once, by the request that first hit the
--    bound, so one anomaly event is recorded per token and not one per rejected request.
--  * playback_sessions.key_window_start and key_window_count: the fixed one-minute window of key
--    requests of one session, updated in one statement. They live on the session row, which the
--    key request has to read anyway, so no table grows with traffic.

CREATE TABLE playback_key_fetches (
    token_hash   bytea PRIMARY KEY
        CONSTRAINT playback_key_fetches_hash_len CHECK (octet_length(token_hash) = 32),
    session_hash bytea NOT NULL REFERENCES playback_sessions (id_hash) ON DELETE CASCADE,
    fetches      integer NOT NULL CONSTRAINT playback_key_fetches_nonneg CHECK (fetches >= 0),
    expires_at   timestamptz NOT NULL,
    exceeded_at  timestamptz
);

-- The sweep deletes by expiry; the foreign key cascade needs the session column.
CREATE INDEX playback_key_fetches_expires_idx ON playback_key_fetches (expires_at);
CREATE INDEX playback_key_fetches_session_idx ON playback_key_fetches (session_hash);

ALTER TABLE playback_sessions
    ADD COLUMN key_window_start timestamptz,
    ADD COLUMN key_window_count integer NOT NULL DEFAULT 0
        CONSTRAINT playback_sessions_key_window_nonneg CHECK (key_window_count >= 0);

-- Anomalies seen by playback (M4-9 adds kinds and a reader). session_hash and asset_id carry no
-- foreign keys on purpose: an event outlives the session and the asset it is about. detail is a
-- small object with numbers only (the bound, the observed count), never a token or a session ID.
CREATE TABLE playback_events (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    session_hash bytea NOT NULL
        CONSTRAINT playback_events_hash_len CHECK (octet_length(session_hash) = 32),
    asset_id     uuid NOT NULL,
    kind         text NOT NULL
        CONSTRAINT playback_events_kind_allowed CHECK (kind IN ('key_replay', 'key_rate')),
    at           timestamptz NOT NULL DEFAULT now(),
    detail       jsonb NOT NULL DEFAULT '{}'
        CONSTRAINT playback_events_detail_small CHECK (pg_column_size(detail) <= 512)
);

CREATE INDEX playback_events_tenant_at_idx ON playback_events (tenant_id, at DESC);

-- +goose Down
DROP TABLE playback_events;
ALTER TABLE playback_sessions DROP COLUMN key_window_count, DROP COLUMN key_window_start;
DROP TABLE playback_key_fetches;
