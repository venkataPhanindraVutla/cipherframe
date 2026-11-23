-- +goose Up
-- The third delivery strategy (ADR 0062, M10-1): 'cdn' puts signed CDN URLs for the delivery bucket
-- into media playlists.

ALTER TABLE playback_settings DROP CONSTRAINT playback_settings_delivery_allowed;
ALTER TABLE playback_settings
    ADD CONSTRAINT playback_settings_delivery_allowed CHECK (delivery IN ('proxy', 'presigned', 'cdn'));

-- +goose Down
UPDATE playback_settings SET delivery = 'presigned' WHERE delivery = 'cdn';
ALTER TABLE playback_settings DROP CONSTRAINT playback_settings_delivery_allowed;
ALTER TABLE playback_settings
    ADD CONSTRAINT playback_settings_delivery_allowed CHECK (delivery IN ('proxy', 'presigned'));
