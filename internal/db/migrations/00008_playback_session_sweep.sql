-- +goose Up
-- M4-6: heartbeat, revocation and the expiry sweep.
--
-- The sweeper marks active sessions ended when they are past their expiry or idle past their
-- tenant's idle timeout. Both conditions are range scans over active rows only, so each gets a
-- partial index (the table's other partial index serves the per-viewer count).
CREATE INDEX playback_sessions_active_expiry_idx ON playback_sessions (expires_at)
    WHERE state = 'active';
CREATE INDEX playback_sessions_active_heartbeat_idx ON playback_sessions (last_heartbeat_at)
    WHERE state = 'active';

-- +goose Down
DROP INDEX playback_sessions_active_heartbeat_idx;
DROP INDEX playback_sessions_active_expiry_idx;
