-- +goose Up
-- M5-3: POST /v1/verify with only a hash looks the hash up among an asset's registered artifacts.
CREATE INDEX asset_artifacts_sha256_idx ON asset_artifacts (sha256);

-- +goose Down
DROP INDEX asset_artifacts_sha256_idx;
