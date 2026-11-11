-- +goose Up
-- M4-9: anomaly signals, the events they raise, and the optional auto-revoke policy.
--
-- playback_events (created by 00007 for key_replay and key_rate) becomes the one table every
-- signal writes to, and the OUTBOX of the webhook system (M7): a delivery worker reads the rows
-- whose delivered_at is NULL, oldest first, posts them, and stamps delivered_at. Nothing in M4
-- delivers anything or sets delivered_at.
--
--  * session_hash is now nullable: a viewer-level event (session_limit, rapid_session_creation)
--    belongs to a viewer, not to one session. A row has a session, a viewer, or both
--    (playback_events_subject).
--  * viewer_id is the embedding application's pseudonymous viewer ID (never an identity
--    Cipherframe learned), copied from the session at the time of the event.
--  * detail stays a small object with numbers only (the bound and the observed count).
--
-- No event stores a token, a session ID or an address. Retention of this table follows with the
-- webhook outbox (M7) and the privacy gate (P11, M6).
ALTER TABLE playback_events
    ALTER COLUMN session_hash DROP NOT NULL,
    ADD COLUMN viewer_id text
        CONSTRAINT playback_events_viewer_len CHECK (viewer_id IS NULL OR char_length(viewer_id) BETWEEN 1 AND 128),
    ADD COLUMN delivered_at timestamptz;

UPDATE playback_events e SET viewer_id = s.viewer_id
FROM playback_sessions s WHERE s.id_hash = e.session_hash;

ALTER TABLE playback_events
    DROP CONSTRAINT playback_events_kind_allowed,
    ADD CONSTRAINT playback_events_kind_allowed CHECK (kind IN (
        'key_replay', 'key_rate', 'session_limit', 'rapid_session_creation', 'segments_without_key')),
    ADD CONSTRAINT playback_events_subject CHECK (session_hash IS NOT NULL OR viewer_id IS NOT NULL);

-- The reader pages (tenant, newest first) on (at, id), and filters on top of that.
DROP INDEX playback_events_tenant_at_idx;
CREATE INDEX playback_events_tenant_at_idx ON playback_events (tenant_id, at DESC, id DESC);
-- Duplicate suppression: "was this kind raised for this session / viewer since T".
CREATE INDEX playback_events_session_kind_idx ON playback_events (session_hash, kind, at DESC)
    WHERE session_hash IS NOT NULL;
CREATE INDEX playback_events_viewer_kind_idx ON playback_events (tenant_id, viewer_id, kind, at DESC)
    WHERE session_hash IS NULL;
-- The webhook outbox (M7): undelivered events, oldest first.
CREATE INDEX playback_events_undelivered_idx ON playback_events (at, id) WHERE delivered_at IS NULL;

-- Thresholds and the auto-revoke policy of a tenant. 0 disables a signal.
--  * anomaly_sessions_per_viewer_10m: more than this many sessions created for one viewer in a
--    sliding 10 minutes is rapid_session_creation.
--  * anomaly_segments_without_key: a session that was served more than this many segments
--    without one successful key fetch is segments_without_key (proxy delivery only).
--  * auto_revoke: the kinds whose events also revoke the session (or, for
--    rapid_session_creation, the viewer's active sessions). Empty means off, the default.
--    session_limit is not allowed: a refused creation has no session to revoke, and revoking a
--    viewer for hitting a limit the tenant set would punish an ordinary retry.
ALTER TABLE playback_settings
    ADD COLUMN anomaly_sessions_per_viewer_10m integer NOT NULL DEFAULT 10
        CONSTRAINT playback_settings_anomaly_sessions_range CHECK (anomaly_sessions_per_viewer_10m BETWEEN 0 AND 1000),
    ADD COLUMN anomaly_segments_without_key integer NOT NULL DEFAULT 30
        CONSTRAINT playback_settings_anomaly_segments_range CHECK (anomaly_segments_without_key BETWEEN 0 AND 100000),
    ADD COLUMN auto_revoke text[] NOT NULL DEFAULT '{}'
        CONSTRAINT playback_settings_auto_revoke_allowed CHECK (
            auto_revoke <@ ARRAY['key_replay', 'key_rate', 'rapid_session_creation', 'segments_without_key']::text[]
            AND cardinality(auto_revoke) <= 4);

-- What the segments_without_key signal needs, kept on the session row so detection is one
-- batched update per segment-count flush and does not depend on the best-effort access log:
--  * segments_served: segment responses served to the session (added at every flush).
--  * key_served_at: when the session was first served the content key.
ALTER TABLE playback_sessions
    ADD COLUMN segments_served bigint NOT NULL DEFAULT 0
        CONSTRAINT playback_sessions_segments_nonneg CHECK (segments_served >= 0),
    ADD COLUMN key_served_at timestamptz;

-- "How many sessions did this viewer create in the last 10 minutes": on every session creation.
CREATE INDEX playback_sessions_viewer_created_idx ON playback_sessions (tenant_id, viewer_id, created_at DESC);

-- +goose Down
DROP INDEX playback_sessions_viewer_created_idx;
ALTER TABLE playback_sessions DROP COLUMN key_served_at, DROP COLUMN segments_served;
ALTER TABLE playback_settings
    DROP COLUMN auto_revoke, DROP COLUMN anomaly_segments_without_key, DROP COLUMN anomaly_sessions_per_viewer_10m;
DROP INDEX playback_events_undelivered_idx;
DROP INDEX playback_events_viewer_kind_idx;
DROP INDEX playback_events_session_kind_idx;
DROP INDEX playback_events_tenant_at_idx;
DELETE FROM playback_events WHERE session_hash IS NULL OR kind NOT IN ('key_replay', 'key_rate');
ALTER TABLE playback_events
    DROP CONSTRAINT playback_events_subject,
    DROP CONSTRAINT playback_events_kind_allowed,
    ADD CONSTRAINT playback_events_kind_allowed CHECK (kind IN ('key_replay', 'key_rate')),
    DROP COLUMN delivered_at,
    DROP COLUMN viewer_id,
    ALTER COLUMN session_hash SET NOT NULL;
CREATE INDEX playback_events_tenant_at_idx ON playback_events (tenant_id, at DESC);
