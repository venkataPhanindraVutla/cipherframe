-- +goose Up
-- M7-1: subtitle tracks (ADR 0044).
--
-- A track is a WebVTT file in the delivery bucket under the asset's prefix (keys.Subtitle). This
-- table holds its metadata; the object is also registered in asset_artifacts (kind 'subtitle') so
-- the purge and the deletion record count it (invariant I6).
--
--  * language is a BCP 47 tag, validated in code; label is the text a player shows. Neither is ever
--    part of a storage key.
--  * At most one track of an asset is the default (the partial unique index); the limit of 20
--    tracks per asset is checked in code under the asset row lock.
--  * origin says whether the track came from an uploaded file or from the transcript import.
--  * duration_ms is the asset's duration when the track was added: it is the length of the track's
--    one-segment media playlist.
--  * sha256 and size_bytes describe the stored bytes (also in the signed manifest).
CREATE TABLE asset_subtitles (
    id          uuid PRIMARY KEY,
    asset_id    uuid NOT NULL REFERENCES assets (id),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    language    text NOT NULL CONSTRAINT asset_subtitles_language_len CHECK (char_length(language) BETWEEN 2 AND 35),
    label       text NOT NULL CONSTRAINT asset_subtitles_label_len CHECK (char_length(label) BETWEEN 1 AND 100),
    is_default  boolean NOT NULL DEFAULT false,
    origin      text NOT NULL CONSTRAINT asset_subtitles_origin_allowed CHECK (origin IN ('upload', 'import')),
    cue_count   integer NOT NULL CONSTRAINT asset_subtitles_cues_positive CHECK (cue_count > 0),
    duration_ms bigint NOT NULL CONSTRAINT asset_subtitles_duration_positive CHECK (duration_ms > 0),
    size_bytes  bigint NOT NULL CONSTRAINT asset_subtitles_size_positive CHECK (size_bytes > 0),
    sha256      bytea NOT NULL CONSTRAINT asset_subtitles_sha256_len CHECK (octet_length(sha256) = 32),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX asset_subtitles_asset_idx ON asset_subtitles (asset_id, created_at, id);
CREATE UNIQUE INDEX asset_subtitles_one_default_idx ON asset_subtitles (asset_id) WHERE is_default;

ALTER TABLE asset_artifacts
    DROP CONSTRAINT asset_artifacts_kind_allowed,
    ADD CONSTRAINT asset_artifacts_kind_allowed
        CHECK (kind IN ('master', 'playlist', 'init', 'segment', 'poster', 'subtitle'));

-- +goose Down
DELETE FROM asset_artifacts WHERE kind = 'subtitle';
ALTER TABLE asset_artifacts
    DROP CONSTRAINT asset_artifacts_kind_allowed,
    ADD CONSTRAINT asset_artifacts_kind_allowed
        CHECK (kind IN ('master', 'playlist', 'init', 'segment', 'poster'));
DROP TABLE asset_subtitles;
