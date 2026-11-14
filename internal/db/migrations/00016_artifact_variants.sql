-- +goose Up
-- FM-3: asset_artifacts says which variant (ADR 0036) an object belongs to, so the masked variant's
-- objects can be registered and removed without touching the original's. Existing rows are the
-- original variant. Deleting an asset still covers both: every row of the asset is purged.
ALTER TABLE asset_artifacts
    ADD COLUMN variant text NOT NULL DEFAULT 'original'
        CONSTRAINT asset_artifacts_variant_allowed CHECK (variant IN ('original', 'masked'));

-- +goose Down
DELETE FROM asset_artifacts WHERE variant <> 'original';
ALTER TABLE asset_artifacts DROP COLUMN variant;
