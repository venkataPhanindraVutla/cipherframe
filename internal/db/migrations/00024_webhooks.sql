-- +goose Up
-- M7-5: webhooks (ADR 0045).
--
--  * webhook_endpoints: where a tenant wants events. The signing secret is stored wrapped by the key
--    provider (never in the clear); a rotation keeps the previous one for 24 hours, like the
--    viewer-authorization callback secret. events is the filter: empty means every kind.
--  * webhook_events is the outbox: one row per event that at least one endpoint wanted, written in
--    the transaction of the state change that caused it, by the triggers below. data holds raw
--    UUIDs (the delivery worker renders them as prefixed IDs); it never holds a viewer address, a
--    user agent, a file name, a key or a token.
--  * webhook_deliveries: one row per (event, endpoint), created with the event, so an endpoint
--    registered later does not receive older events. state is pending until a 2xx (succeeded) or
--    the last attempt fails (dead, the dead-letter list). A replay sets it back to pending.
--  * webhook_attempts: what each attempt got back: the status code, the duration, a failure class
--    and a small sanitized excerpt of the response. Never headers, never the full body.
CREATE TABLE webhook_endpoints (
    id                   uuid PRIMARY KEY,
    tenant_id            uuid NOT NULL REFERENCES tenants (id),
    url                  text NOT NULL
        CONSTRAINT webhook_endpoints_url CHECK (url ~ '^https://' AND char_length(url) <= 2048),
    events               text[] NOT NULL DEFAULT '{}'
        CONSTRAINT webhook_endpoints_events_allowed CHECK (events <@ ARRAY[
            'asset.ready', 'asset.failed', 'asset.deleted', 'session.revoked', 'session.anomaly', 'retention.expired']::text[]),
    enabled              boolean NOT NULL DEFAULT true,
    secret_envelope      bytea NOT NULL,
    secret_version       integer NOT NULL CONSTRAINT webhook_endpoints_secret_version CHECK (secret_version >= 1),
    prev_secret_envelope bytea,
    prev_secret_version  integer,
    secret_rotated_at    timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_endpoints_prev_secret CHECK ((prev_secret_envelope IS NULL) = (prev_secret_version IS NULL))
);

CREATE INDEX webhook_endpoints_tenant_idx ON webhook_endpoints (tenant_id, created_at, id);

CREATE TABLE webhook_events (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    kind        text NOT NULL
        CONSTRAINT webhook_events_kind_allowed CHECK (kind IN (
            'asset.ready', 'asset.failed', 'asset.deleted', 'session.revoked', 'session.anomaly', 'retention.expired')),
    data        jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_events_created_idx ON webhook_events (created_at);

CREATE TABLE webhook_deliveries (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    event_id        uuid NOT NULL REFERENCES webhook_events (id) ON DELETE CASCADE,
    endpoint_id     uuid NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    state           text NOT NULL DEFAULT 'pending'
        CONSTRAINT webhook_deliveries_state_allowed CHECK (state IN ('pending', 'succeeded', 'dead')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    last_status     integer,
    last_attempt_at timestamptz,
    completed_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_deliveries_once UNIQUE (event_id, endpoint_id)
);

-- The worker's claim: due pending deliveries, oldest due first.
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at) WHERE state = 'pending';
-- The admin list: one endpoint, newest first, optionally by state.
CREATE INDEX webhook_deliveries_endpoint_idx ON webhook_deliveries (endpoint_id, created_at DESC, id DESC);
CREATE INDEX webhook_deliveries_tenant_idx ON webhook_deliveries (tenant_id, created_at DESC, id DESC);

CREATE TABLE webhook_attempts (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    delivery_id uuid NOT NULL REFERENCES webhook_deliveries (id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    number      integer NOT NULL,
    at          timestamptz NOT NULL,
    status_code integer,
    duration_ms integer NOT NULL,
    error       text CONSTRAINT webhook_attempts_error_len CHECK (error IS NULL OR char_length(error) <= 64),
    excerpt     text NOT NULL DEFAULT '' CONSTRAINT webhook_attempts_excerpt_len CHECK (char_length(excerpt) <= 256)
);

CREATE INDEX webhook_attempts_delivery_idx ON webhook_attempts (delivery_id, id);

-- webhook_emit records an event and a delivery for each enabled endpoint of the tenant that wants
-- it, and does nothing when none does. It runs inside the transaction of the caller, which is the
-- point: the event exists if and only if the change that caused it committed.
-- +goose StatementBegin
CREATE FUNCTION webhook_emit(p_id uuid, p_tenant uuid, p_kind text, p_data jsonb, p_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM webhook_endpoints e
        WHERE e.tenant_id = p_tenant AND e.enabled AND (cardinality(e.events) = 0 OR p_kind = ANY (e.events))
    ) THEN
        RETURN;
    END IF;
    INSERT INTO webhook_events (id, tenant_id, kind, data, occurred_at) VALUES (p_id, p_tenant, p_kind, p_data, p_at);
    INSERT INTO webhook_deliveries (id, tenant_id, event_id, endpoint_id, next_attempt_at)
    SELECT gen_random_uuid(), p_tenant, p_id, e.id, now()
    FROM webhook_endpoints e
    WHERE e.tenant_id = p_tenant AND e.enabled AND (cardinality(e.events) = 0 OR p_kind = ANY (e.events));
END $$;
-- +goose StatementEnd

-- The functions run as their owner (the role that ran the migrations), so any role the service runs
-- as can change an asset or a session: the role needs no access to the webhook tables. The search
-- path of the migrating session is pinned into them. webhook_emit takes a tenant and writes events
-- for it, so no other role may call it.
REVOKE EXECUTE ON FUNCTION webhook_emit(uuid, uuid, text, jsonb, timestamptz) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION webhook_on_asset_state() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.state = 'ready' THEN
        PERFORM webhook_emit(gen_random_uuid(), NEW.tenant_id, 'asset.ready',
            jsonb_build_object('asset_id', NEW.id, 'state', NEW.state), NEW.updated_at);
    ELSIF NEW.state = 'failed' THEN
        PERFORM webhook_emit(gen_random_uuid(), NEW.tenant_id, 'asset.failed',
            jsonb_build_object('asset_id', NEW.id, 'state', NEW.state, 'failure_code', NEW.failure_code), NEW.updated_at);
    ELSIF NEW.state = 'deleted' THEN
        PERFORM webhook_emit(gen_random_uuid(), NEW.tenant_id, 'asset.deleted',
            jsonb_build_object('asset_id', NEW.id, 'state', NEW.state, 'reason', NEW.deletion_reason), COALESCE(NEW.deleted_at, NEW.updated_at));
    ELSIF NEW.state = 'deleting' AND NEW.deletion_reason = 'retention' THEN
        PERFORM webhook_emit(gen_random_uuid(), NEW.tenant_id, 'retention.expired',
            jsonb_build_object('asset_id', NEW.id, 'state', NEW.state, 'expires_at', NEW.expires_at), COALESCE(NEW.deletion_requested_at, NEW.updated_at));
    END IF;
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER webhook_asset_state AFTER UPDATE OF state ON assets
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state) EXECUTE FUNCTION webhook_on_asset_state();

-- A session is revoked once (only an active session changes), so each revocation is one event. The
-- session is named by the 8-character fingerprint the access log and the events API use.
-- +goose StatementBegin
CREATE FUNCTION webhook_on_session_revoked() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM webhook_emit(gen_random_uuid(), NEW.tenant_id, 'session.revoked',
        jsonb_build_object('asset_id', NEW.asset_id, 'viewer_id', NEW.viewer_id,
            'session', substr(encode(sha256(NEW.id_hash || uuid_send(NEW.tenant_id)), 'hex'), 1, 8),
            'reason', NEW.revoke_reason),
        COALESCE(NEW.revoked_at, now()));
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER webhook_session_revoked AFTER UPDATE OF state ON playback_sessions
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state = 'revoked') EXECUTE FUNCTION webhook_on_session_revoked();

-- Anomalies are folded into the outbox: the webhook event has the ID of the playback_events row, so
-- the events API and the delivery name the same event. playback_events.delivered_at is no longer
-- used (the column stays; nothing reads it) and its index goes.
-- +goose StatementBegin
CREATE FUNCTION webhook_on_anomaly() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM webhook_emit(NEW.id, NEW.tenant_id, 'session.anomaly',
        jsonb_build_object('kind', NEW.kind, 'asset_id', NEW.asset_id, 'viewer_id', NEW.viewer_id,
            'session', CASE WHEN NEW.session_hash IS NULL THEN NULL
                ELSE substr(encode(sha256(NEW.session_hash || uuid_send(NEW.tenant_id)), 'hex'), 1, 8) END,
            'detail', NEW.detail),
        NEW.at);
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER webhook_anomaly AFTER INSERT ON playback_events
    FOR EACH ROW EXECUTE FUNCTION webhook_on_anomaly();

DROP INDEX playback_events_undelivered_idx;

-- +goose Down
CREATE INDEX playback_events_undelivered_idx ON playback_events (at, id) WHERE delivered_at IS NULL;
DROP TRIGGER webhook_anomaly ON playback_events;
DROP FUNCTION webhook_on_anomaly();
DROP TRIGGER webhook_session_revoked ON playback_sessions;
DROP FUNCTION webhook_on_session_revoked();
DROP TRIGGER webhook_asset_state ON assets;
DROP FUNCTION webhook_on_asset_state();
DROP FUNCTION webhook_emit(uuid, uuid, text, jsonb, timestamptz);
DROP TABLE webhook_attempts;
DROP TABLE webhook_deliveries;
DROP TABLE webhook_events;
DROP TABLE webhook_endpoints;
