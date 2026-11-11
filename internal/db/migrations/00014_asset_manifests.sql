-- +goose Up
-- M5-1: the signed integrity manifest of an asset (ADR 0033).
--
-- One row per ready asset, written in the same transaction that moves the asset to ready, so a
-- ready asset always has its manifest. The envelope is the DSSE envelope as JSON (payloadType,
-- base64 payload, signatures); the payload is the canonical manifest. It lives in the database
-- only and is not an object in the delivery bucket.
--
--  * key_id is the signing key that made the first signature (informational; the envelope is
--    authoritative).
--  * payload_sha256 is SHA-256 of the decoded payload (the canonical manifest bytes).
--  * top_root is the top-level Merkle root recorded in the manifest.
--
-- A processing retry deletes the row before it builds a new manifest, so the insert is a plain
-- INSERT: a duplicate would be a bug.
CREATE TABLE asset_manifests (
    asset_id       uuid PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    key_id         text NOT NULL
        CONSTRAINT asset_manifests_key_id_nonempty CHECK (key_id <> ''),
    payload_sha256 bytea NOT NULL
        CONSTRAINT asset_manifests_payload_sha256_len CHECK (octet_length(payload_sha256) = 32),
    top_root       bytea NOT NULL
        CONSTRAINT asset_manifests_top_root_len CHECK (octet_length(top_root) = 32),
    envelope       jsonb NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX asset_manifests_tenant_idx ON asset_manifests (tenant_id, asset_id);

-- +goose Down
DROP TABLE asset_manifests;
