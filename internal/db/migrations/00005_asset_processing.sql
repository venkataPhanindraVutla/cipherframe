-- +goose Up
-- Processing results and the derived-artifact registry (ADR 0024, M3).
--
-- source_sha256 and source_size_bytes are measured by the worker while it streams the source out
-- of the object store (one pass: download, hash, write), so they describe the bytes that were
-- actually transcoded. duration_ms and renditions (a JSON summary: name, size, bandwidth, codecs,
-- segment count) are set when the asset becomes ready. progress is 0-100 and only a hint for
-- clients; it is written at most every few seconds.

ALTER TABLE assets
    ADD COLUMN source_sha256     bytea
        CONSTRAINT assets_source_sha256_len CHECK (source_sha256 IS NULL OR octet_length(source_sha256) = 32),
    ADD COLUMN source_size_bytes bigint
        CONSTRAINT assets_source_size_positive CHECK (source_size_bytes IS NULL OR source_size_bytes > 0),
    ADD COLUMN duration_ms       bigint
        CONSTRAINT assets_duration_positive CHECK (duration_ms IS NULL OR duration_ms > 0),
    ADD COLUMN renditions        jsonb,
    ADD COLUMN progress          smallint NOT NULL DEFAULT 0
        CONSTRAINT assets_progress_range CHECK (progress BETWEEN 0 AND 100);

-- Every object the pipeline derives from an asset (invariant I6): the master and media playlists,
-- init segments, encrypted media segments and, later, posters. A derived object that is not
-- registered here would be missed by deletion, integrity checks and crypto-shredding audits.
-- sha256 is the hash of the bytes as stored, so for a segment it covers the ciphertext.
-- The pair (bucket, object_key) is unique: an object belongs to exactly one asset.
CREATE TABLE asset_artifacts (
    asset_id    uuid NOT NULL REFERENCES assets (id),
    kind        text NOT NULL
        CONSTRAINT asset_artifacts_kind_allowed CHECK (kind IN ('master', 'playlist', 'init', 'segment', 'poster')),
    rendition   text,
    bucket      text NOT NULL
        CONSTRAINT asset_artifacts_bucket_allowed CHECK (bucket IN ('source', 'delivery')),
    object_key  text NOT NULL CONSTRAINT asset_artifacts_key_nonempty CHECK (object_key <> ''),
    size_bytes  bigint NOT NULL CONSTRAINT asset_artifacts_size_nonneg CHECK (size_bytes >= 0),
    sha256      bytea NOT NULL CONSTRAINT asset_artifacts_sha256_len CHECK (octet_length(sha256) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket, object_key)
);

CREATE INDEX asset_artifacts_asset_idx ON asset_artifacts (asset_id, kind, rendition);

-- +goose Down
DROP TABLE asset_artifacts;
ALTER TABLE assets
    DROP COLUMN progress,
    DROP COLUMN renditions,
    DROP COLUMN duration_ms,
    DROP COLUMN source_size_bytes,
    DROP COLUMN source_sha256;
