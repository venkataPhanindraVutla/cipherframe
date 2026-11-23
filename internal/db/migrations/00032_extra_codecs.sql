-- +goose Up
-- M10-3: optional HEVC and AV1 renditions (ADR 0064, ADR 0067).
--
--  * playback_settings.extra_codecs: the tenant's setting, any of 'hevc' and 'av1'; empty means H.264 only.
--  * assets.extra_codecs: the setting as it was when the asset was created. It is what the worker makes,
--    so a later change of the setting never touches an asset that is already uploaded.
--  * assets.extra_codec_failures: the codecs of extra_codecs that could not be made, each with a fixed
--    reason code, recorded when the asset becomes ready (the H.264 ladder still completes).
--  * worker_capabilities: one row per running worker process with the extra codecs its FFmpeg can
--    encode and when it last said so. The settings endpoint refuses a codec no recent row lists.
ALTER TABLE playback_settings
    ADD COLUMN extra_codecs text[] NOT NULL DEFAULT '{}'
        CONSTRAINT playback_settings_extra_codecs_allowed
        CHECK (extra_codecs <@ ARRAY['hevc', 'av1']::text[] AND cardinality(extra_codecs) <= 2);

ALTER TABLE assets
    ADD COLUMN extra_codecs text[] NOT NULL DEFAULT '{}'
        CONSTRAINT assets_extra_codecs_allowed
        CHECK (extra_codecs <@ ARRAY['hevc', 'av1']::text[] AND cardinality(extra_codecs) <= 2),
    ADD COLUMN extra_codec_failures jsonb NOT NULL DEFAULT '[]'
        CONSTRAINT assets_extra_codec_failures_array CHECK (jsonb_typeof(extra_codec_failures) = 'array');

CREATE TABLE worker_capabilities (
    worker_id    uuid PRIMARY KEY,
    codecs       text[] NOT NULL
        CONSTRAINT worker_capabilities_codecs_allowed
        CHECK (codecs <@ ARRAY['hevc', 'av1']::text[] AND cardinality(codecs) <= 2),
    started_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL
);

CREATE INDEX worker_capabilities_last_seen_idx ON worker_capabilities (last_seen_at);

-- +goose Down
DROP TABLE worker_capabilities;
ALTER TABLE assets DROP COLUMN extra_codec_failures, DROP COLUMN extra_codecs;
ALTER TABLE playback_settings DROP COLUMN extra_codecs;
