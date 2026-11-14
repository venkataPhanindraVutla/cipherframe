-- +goose Up
-- FM-1: asset variants (ADR 0036). An asset always has an 'original' variant. An asset created with
-- mask_faces also gets a 'masked' variant later (FM-3), with its own HLS tree and its own content key.
--
--  * assets.mask_faces is chosen at creation. masking_state is NULL unless mask_faces is set; it is
--    'pending' once the original is ready, then 'ready' or 'failed'. faces_detected is the count the
--    masker reports.
--  * content_keys is unique on (asset_id, variant): one key per variant, so a key of one variant never
--    decrypts the other. Crypto-shredding still deletes every row of the asset.
--  * playback_sessions.variant binds a session to one variant for its whole life; edge serves only
--    that variant's bytes and key.
--
-- asset_artifacts and asset_manifests are left as they are: the edge resolves storage keys from the
-- asset and the session's variant (internal/storage/keys), not from those tables. FM-3 adds the
-- masked variant's artifacts and manifest entries.

ALTER TABLE assets
    ADD COLUMN mask_faces boolean NOT NULL DEFAULT false,
    ADD COLUMN masking_state text
        CONSTRAINT assets_masking_state_allowed CHECK (masking_state IN ('pending', 'ready', 'failed')),
    ADD COLUMN faces_detected integer
        CONSTRAINT assets_faces_detected_nonneg CHECK (faces_detected >= 0),
    ADD CONSTRAINT assets_masking_state_needs_mask_faces CHECK (mask_faces OR masking_state IS NULL);

ALTER TABLE content_keys
    ADD COLUMN variant text NOT NULL DEFAULT 'original'
        CONSTRAINT content_keys_variant_allowed CHECK (variant IN ('original', 'masked')),
    DROP CONSTRAINT content_keys_asset_id_key,
    ADD CONSTRAINT content_keys_asset_id_variant_key UNIQUE (asset_id, variant);

ALTER TABLE playback_sessions
    ADD COLUMN variant text NOT NULL DEFAULT 'original'
        CONSTRAINT playback_sessions_variant_allowed CHECK (variant IN ('original', 'masked'));

-- +goose Down
ALTER TABLE playback_sessions DROP COLUMN variant;

DELETE FROM content_keys WHERE variant <> 'original';
ALTER TABLE content_keys
    DROP CONSTRAINT content_keys_asset_id_variant_key,
    ADD CONSTRAINT content_keys_asset_id_key UNIQUE (asset_id),
    DROP COLUMN variant;

ALTER TABLE assets
    DROP COLUMN faces_detected,
    DROP COLUMN masking_state,
    DROP COLUMN mask_faces;
