-- +goose Up
-- One envelope-encrypted content key per asset (invariant I7, M2-1). The key is wrapped by a
-- key-encryption key held by a key provider (ADR 0019, ADR 0020); the row records which provider,
-- KEK id and KEK version wrapped it so it stays readable after the KEK rotates, and so M2-4 can
-- find the rows that still use an old KEK version.
--
-- The UNIQUE constraint on asset_id is what enforces "one active content key per asset".
-- Crypto-shredding (M6) deletes the row; it is never flagged. The column holds only ciphertext,
-- never a plaintext key.

CREATE TABLE content_keys (
    id               uuid PRIMARY KEY,
    asset_id         uuid NOT NULL REFERENCES assets (id),
    provider         text NOT NULL CONSTRAINT content_keys_provider_nonempty CHECK (provider <> ''),
    kek_key_id       text NOT NULL CONSTRAINT content_keys_kek_key_id_nonempty CHECK (kek_key_id <> ''),
    kek_version      text NOT NULL CONSTRAINT content_keys_kek_version_nonempty CHECK (kek_version <> ''),
    envelope_version smallint NOT NULL CONSTRAINT content_keys_envelope_version_positive CHECK (envelope_version >= 1),
    wrapped          bytea NOT NULL CONSTRAINT content_keys_wrapped_nonempty CHECK (length(wrapped) > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    rewrapped_at     timestamptz,
    CONSTRAINT content_keys_asset_id_key UNIQUE (asset_id)
);

-- Serves the re-wrap listing: rows of one provider, KEK id and KEK version, in keyset order.
CREATE INDEX content_keys_kek_idx ON content_keys (provider, kek_key_id, kek_version, id);

-- +goose Down
DROP TABLE content_keys;
