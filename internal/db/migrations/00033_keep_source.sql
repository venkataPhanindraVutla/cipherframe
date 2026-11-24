-- +goose Up
-- H-3: optional deletion of the uploaded original once the asset is ready.
--
--  * privacy_settings.keep_source: the tenant's setting; true (the default) keeps the original.
--  * assets.keep_source: the setting as it was when the asset was created, so a later change never
--    reaches an asset that is already uploaded.
--  * assets.source_deleted_at: when the asset.drop_source job deleted the original; NULL while kept.
ALTER TABLE privacy_settings ADD COLUMN keep_source boolean NOT NULL DEFAULT true;

ALTER TABLE assets
    ADD COLUMN keep_source boolean NOT NULL DEFAULT true,
    ADD COLUMN source_deleted_at timestamptz;

-- +goose Down
ALTER TABLE assets DROP COLUMN source_deleted_at, DROP COLUMN keep_source;
ALTER TABLE privacy_settings DROP COLUMN keep_source;
