-- +goose Up
-- Delivery strategy of a tenant's playback (ADR 0032, M4-5): 'proxy' serves segments through edge,
-- 'presigned' puts short-lived storage URLs for the delivery bucket into media playlists.

ALTER TABLE playback_settings
    ADD COLUMN delivery text NOT NULL DEFAULT 'proxy'
        CONSTRAINT playback_settings_delivery_allowed CHECK (delivery IN ('proxy', 'presigned'));

-- +goose Down
ALTER TABLE playback_settings DROP COLUMN delivery;
