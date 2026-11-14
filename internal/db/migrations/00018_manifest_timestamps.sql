-- +goose Up
-- M5-5: an optional RFC 3161 timestamp token for a manifest (ADR 0041).
--
-- The token stamps SHA-256 of the manifest payload, which is already payload_sha256, so no
-- imprint column is needed. The three columns are all set or all null. A re-signed manifest
-- (masking) is a new row, so its token starts out empty.
ALTER TABLE asset_manifests
    ADD COLUMN ts_token    bytea,
    ADD COLUMN ts_gen_time timestamptz,
    ADD COLUMN ts_tsa_url  text,
    ADD CONSTRAINT asset_manifests_ts_all_or_none CHECK (
        (ts_token IS NULL AND ts_gen_time IS NULL AND ts_tsa_url IS NULL)
        OR (ts_token IS NOT NULL AND ts_gen_time IS NOT NULL AND ts_tsa_url IS NOT NULL)
    );

-- +goose Down
ALTER TABLE asset_manifests
    DROP CONSTRAINT asset_manifests_ts_all_or_none,
    DROP COLUMN ts_token,
    DROP COLUMN ts_gen_time,
    DROP COLUMN ts_tsa_url;
