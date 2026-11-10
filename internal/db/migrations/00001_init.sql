-- +goose Up
-- Initial schema (ADR 0007, 0009, 0016). Identifiers are UUIDv7 values generated in Go, so no
-- column has a database-side default id. Compatible with PostgreSQL 16 and newer (ADR 0017).

CREATE TABLE tenants (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE clients (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE INDEX clients_tenant_id_idx ON clients (tenant_id, created_at, id);

CREATE TABLE api_keys (
    id                      uuid PRIMARY KEY,
    client_id               uuid NOT NULL REFERENCES clients (id),
    name                    text NOT NULL,
    prefix                  text NOT NULL UNIQUE,
    secret_hash             bytea NOT NULL,
    pepper_version          integer NOT NULL,
    scopes                  text[] NOT NULL,
    previous_secret_hash    bytea,
    previous_pepper_version integer,
    previous_valid_until    timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    rotated_at              timestamptz,
    revoked_at              timestamptz,
    last_used_at            timestamptz,
    CONSTRAINT api_keys_previous_all_or_none CHECK (
        (previous_secret_hash IS NULL
            AND previous_pepper_version IS NULL
            AND previous_valid_until IS NULL)
        OR (previous_secret_hash IS NOT NULL
            AND previous_pepper_version IS NOT NULL
            AND previous_valid_until IS NOT NULL)
    ),
    CONSTRAINT api_keys_scopes_allowed CHECK (
        scopes <@ ARRAY['assets:read', 'assets:write', 'sessions:write', 'webhooks:manage', 'admin']::text[]
    )
);

CREATE INDEX api_keys_client_id_idx ON api_keys (client_id);

CREATE TABLE assets (
    id                   uuid PRIMARY KEY,
    tenant_id            uuid NOT NULL REFERENCES tenants (id),
    created_by_client_id uuid NOT NULL REFERENCES clients (id),
    state                text NOT NULL
        CONSTRAINT assets_state_allowed CHECK (
            state IN ('created', 'uploading', 'committed', 'processing', 'ready', 'failed', 'deleted')
        ),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX assets_tenant_id_idx ON assets (tenant_id, created_at, id);

-- Audit rows deliberately have no foreign keys: they must outlive the tenants, clients, keys and
-- assets they describe.
CREATE TABLE audit_events (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    client_id  uuid,
    api_key_id uuid,
    action     text NOT NULL,
    target     text,
    request_id text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_tenant_created_idx ON audit_events (tenant_id, created_at);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE assets;
DROP TABLE api_keys;
DROP TABLE clients;
DROP TABLE tenants;
