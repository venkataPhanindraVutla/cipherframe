-- +goose Up
-- Asset lifecycle and upload bookkeeping (ADR 0025, 0026). The new asset columns are nullable
-- so rows written by earlier tasks stay valid; the application always sets them for assets created
-- through the API.
--
-- source_key is the object key of the upload in the source bucket. It carries a random component
-- (internal/storage/keys) so it cannot be derived from IDs, and it is never returned or logged.
-- No original file name is stored anywhere (privacy gate P11 is pending).

ALTER TABLE assets
    ADD COLUMN size_bytes             bigint
        CONSTRAINT assets_size_bytes_positive CHECK (size_bytes IS NULL OR size_bytes > 0),
    ADD COLUMN content_type           text,
    ADD COLUMN upload_method          text
        CONSTRAINT assets_upload_method_allowed CHECK (upload_method IS NULL OR upload_method IN ('tus', 'multipart')),
    ADD COLUMN source_key             text,
    ADD COLUMN s3_upload_id           text,
    ADD COLUMN upload_expires_at      timestamptz,
    ADD COLUMN committed_at           timestamptz,
    ADD COLUMN processing_started_at  timestamptz,
    ADD COLUMN ready_at               timestamptz,
    ADD COLUMN failed_at              timestamptz,
    ADD COLUMN failure_code           text;

CREATE UNIQUE INDEX assets_source_key_idx ON assets (source_key) WHERE source_key IS NOT NULL;

-- One short-lived token per asset, bound to that asset. Only the SHA-256 of the token is stored:
-- the token is 256 random bits, so a fast hash is enough and a database reader cannot use it.
CREATE TABLE upload_tokens (
    token_hash bytea PRIMARY KEY CONSTRAINT upload_tokens_hash_len CHECK (octet_length(token_hash) = 32),
    asset_id   uuid NOT NULL UNIQUE REFERENCES assets (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Parts of a multipart upload that edge streamed into the object store.
CREATE TABLE upload_parts (
    asset_id    uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    part_number integer NOT NULL CONSTRAINT upload_parts_number_range CHECK (part_number BETWEEN 1 AND 10000),
    etag        text NOT NULL,
    size_bytes  bigint NOT NULL CONSTRAINT upload_parts_size_positive CHECK (size_bytes > 0),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, part_number)
);

-- +goose Down
DROP TABLE upload_parts;
DROP TABLE upload_tokens;
DROP INDEX assets_source_key_idx;
ALTER TABLE assets
    DROP COLUMN failure_code,
    DROP COLUMN failed_at,
    DROP COLUMN ready_at,
    DROP COLUMN processing_started_at,
    DROP COLUMN committed_at,
    DROP COLUMN upload_expires_at,
    DROP COLUMN s3_upload_id,
    DROP COLUMN source_key,
    DROP COLUMN upload_method,
    DROP COLUMN content_type,
    DROP COLUMN size_bytes;
