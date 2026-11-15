-- +goose Up
-- M7-2: thumbnails (ADR 0046).
--
-- A variant's poster, sprite sheet and WebVTT thumbnail track are objects in the delivery bucket
-- under the variant's HLS prefix. They are registered in asset_artifacts, per variant, so the purge
-- and the deletion record count them (invariant I6). No new table: nothing about them is metadata
-- beyond the object itself (the track holds the tile geometry).
ALTER TABLE asset_artifacts
    DROP CONSTRAINT asset_artifacts_kind_allowed,
    ADD CONSTRAINT asset_artifacts_kind_allowed
        CHECK (kind IN ('master', 'playlist', 'init', 'segment', 'poster', 'subtitle', 'sprite', 'thumbnails'));

-- +goose Down
DELETE FROM asset_artifacts WHERE kind IN ('sprite', 'thumbnails');
ALTER TABLE asset_artifacts
    DROP CONSTRAINT asset_artifacts_kind_allowed,
    ADD CONSTRAINT asset_artifacts_kind_allowed
        CHECK (kind IN ('master', 'playlist', 'init', 'segment', 'poster', 'subtitle'));
