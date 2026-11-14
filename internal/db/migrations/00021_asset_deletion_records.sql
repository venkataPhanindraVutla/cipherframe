-- +goose Up
-- M6-3: the signed deletion record of an asset (ADR 0033, ADR 0040, ADR 0042).
--
-- One row per deleted asset, written in the transaction that moves the asset to its tombstone
-- state, so a deleted asset always has its record. The envelope is the DSSE envelope as JSON
-- (payloadType, base64 payload, signatures); the payload is the canonical record. It names counts,
-- sizes and key IDs, never object keys or key material, and it outlives everything else of the
-- asset: nothing deletes it.
--
--  * key_id is the signing key that made the first signature (informational; the envelope is
--    authoritative).
--  * payload_sha256 is SHA-256 of the decoded payload.
--  * reason, requested_at and completed_at repeat what the payload says so a lookup does not need
--    to parse the envelope.
CREATE TABLE asset_deletion_records (
    asset_id       uuid PRIMARY KEY REFERENCES assets (id),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    reason         text NOT NULL
        CONSTRAINT asset_deletion_records_reason_allowed CHECK (reason IN ('requested', 'retention')),
    requested_at   timestamptz NOT NULL,
    completed_at   timestamptz NOT NULL,
    key_id         text NOT NULL
        CONSTRAINT asset_deletion_records_key_id_nonempty CHECK (key_id <> ''),
    payload_sha256 bytea NOT NULL
        CONSTRAINT asset_deletion_records_payload_sha256_len CHECK (octet_length(payload_sha256) = 32),
    envelope       jsonb NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX asset_deletion_records_tenant_idx ON asset_deletion_records (tenant_id, completed_at);

-- +goose Down
DROP TABLE asset_deletion_records;
