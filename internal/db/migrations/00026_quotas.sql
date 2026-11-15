-- +goose Up
-- M7-6: quotas and per-client limits (ADR 0047).
--
--  * tenant_quotas holds a tenant's limits; client_quotas holds a client's lower overrides. A NULL
--    column, or no row at all, means unlimited (for a client: no override of its own). Nothing is
--    limited until an operator sets a limit.
--  * transcode_charges is the ledger behind the monthly transcode minutes: one row per asset, written
--    once when the pipeline has probed the source (a retried job finds its row and charges nothing
--    more). The month's usage is the sum of duration_ms over the month (UTC) of charged_at.
--  * The session counts read playback_sessions; the partial index keeps them cheap per tenant and
--    per client.
CREATE TABLE tenant_quotas (
    tenant_id                   uuid PRIMARY KEY REFERENCES tenants (id),
    storage_bytes               bigint
        CONSTRAINT tenant_quotas_storage_positive CHECK (storage_bytes IS NULL OR storage_bytes > 0),
    transcode_minutes_per_month integer
        CONSTRAINT tenant_quotas_minutes_positive CHECK (transcode_minutes_per_month IS NULL OR transcode_minutes_per_month > 0),
    concurrent_sessions         integer
        CONSTRAINT tenant_quotas_sessions_positive CHECK (concurrent_sessions IS NULL OR concurrent_sessions > 0),
    requests_per_minute         integer
        CONSTRAINT tenant_quotas_requests_positive CHECK (requests_per_minute IS NULL OR requests_per_minute > 0),
    updated_at                  timestamptz NOT NULL
);

CREATE TABLE client_quotas (
    client_id                   uuid PRIMARY KEY REFERENCES clients (id),
    tenant_id                   uuid NOT NULL REFERENCES tenants (id),
    storage_bytes               bigint
        CONSTRAINT client_quotas_storage_positive CHECK (storage_bytes IS NULL OR storage_bytes > 0),
    transcode_minutes_per_month integer
        CONSTRAINT client_quotas_minutes_positive CHECK (transcode_minutes_per_month IS NULL OR transcode_minutes_per_month > 0),
    concurrent_sessions         integer
        CONSTRAINT client_quotas_sessions_positive CHECK (concurrent_sessions IS NULL OR concurrent_sessions > 0),
    requests_per_minute         integer
        CONSTRAINT client_quotas_requests_positive CHECK (requests_per_minute IS NULL OR requests_per_minute > 0),
    updated_at                  timestamptz NOT NULL
);

CREATE TABLE transcode_charges (
    asset_id    uuid PRIMARY KEY REFERENCES assets (id),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    client_id   uuid NOT NULL REFERENCES clients (id),
    duration_ms bigint NOT NULL CONSTRAINT transcode_charges_duration_nonneg CHECK (duration_ms >= 0),
    charged_at  timestamptz NOT NULL
);

CREATE INDEX transcode_charges_tenant_idx ON transcode_charges (tenant_id, charged_at);
CREATE INDEX transcode_charges_client_idx ON transcode_charges (client_id, charged_at);

CREATE INDEX playback_sessions_tenant_active_idx ON playback_sessions (tenant_id, client_id) WHERE state = 'active';

-- +goose Down
DROP INDEX playback_sessions_tenant_active_idx;
DROP TABLE transcode_charges;
DROP TABLE client_quotas;
DROP TABLE tenant_quotas;
