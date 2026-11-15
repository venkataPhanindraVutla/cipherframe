-- +goose Up
-- M7-3: the overlay watermark policy (ADR 0048).
--
--  * overlay_settings is a tenant's overlay policy. No row means the defaults, which are off.
--  * playback_sessions.overlay_code is the short code the player shows; it is derived from the
--    session (not the session ID) and stored so a tenant can map a leaked code back to the session
--    and viewer. The retention sweep sets it to NULL after the access-trail window.
CREATE TABLE overlay_settings (
    tenant_id          uuid PRIMARY KEY REFERENCES tenants (id),
    enabled            boolean NOT NULL,
    template           text NOT NULL
        CONSTRAINT overlay_settings_template_len CHECK (char_length(template) BETWEEN 1 AND 120),
    opacity            double precision NOT NULL
        CONSTRAINT overlay_settings_opacity_range CHECK (opacity >= 0.05 AND opacity <= 0.8),
    font_size_fraction double precision NOT NULL
        CONSTRAINT overlay_settings_size_range CHECK (font_size_fraction >= 0.015 AND font_size_fraction <= 0.1),
    color              text NOT NULL
        CONSTRAINT overlay_settings_color_format CHECK (color ~ '^#[0-9A-F]{6}$'),
    updated_at         timestamptz NOT NULL
);

ALTER TABLE playback_sessions
    ADD COLUMN overlay_code text
        CONSTRAINT playback_sessions_overlay_code_format CHECK (overlay_code IS NULL OR overlay_code ~ '^[A-Z2-9]{8}$');

CREATE INDEX playback_sessions_overlay_code_idx ON playback_sessions (tenant_id, overlay_code)
    WHERE overlay_code IS NOT NULL;

-- +goose Down
DROP INDEX playback_sessions_overlay_code_idx;
ALTER TABLE playback_sessions DROP COLUMN overlay_code;
DROP TABLE overlay_settings;
