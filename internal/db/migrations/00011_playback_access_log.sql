-- +goose Up
-- M4-7: the access trail (invariant I10) and the per-tenant privacy settings that shape it.
--
-- playback_access_log holds one row per access event: who (the viewer ID the embedding application
-- chose, never an identity Cipherframe learned), when, and what kind of event. It never holds a
-- session ID or a token (only the SHA-256 of the session ID), never which segment or position was
-- watched (segment requests are only counted, per session and flush interval), and holds a
-- viewer's IP address and user agent only when the tenant turned that on in privacy_settings.
--
-- The table is PARTITIONED BY RANGE (at), one partition per calendar month in UTC, so retention
-- (M6-4) can drop whole months instead of deleting rows. There is deliberately NO default
-- partition: a missing partition makes an insert fail loudly instead of silently piling rows into
-- one table that can never be dropped. The edge role's sweeper creates the current and next two
-- months on every run (playback_access_log_ensure_partition); this migration creates the current
-- and next month.
--
-- No foreign keys: it is an append-only, high-volume table, and a foreign key would check a
-- tenants row on every insert and pin old partitions to live rows. Reads are always scoped by
-- tenant_id.
CREATE SEQUENCE playback_access_log_id_seq;

CREATE TABLE playback_access_log (
    -- id orders rows with equal timestamps for cursor pagination. It is not unique across
    -- partitions by constraint (a partitioned table's key must include the partition key), but it
    -- comes from one sequence, so it is unique in practice.
    id              bigint NOT NULL DEFAULT nextval('playback_access_log_id_seq'),
    tenant_id       uuid NOT NULL,
    asset_id        uuid,
    -- SHA-256 of the session ID. NULL only for a refused session creation (there is no session).
    session_hash    bytea
        CONSTRAINT playback_access_log_hash_len CHECK (session_hash IS NULL OR octet_length(session_hash) = 32),
    -- NULL when the viewer is not known (a refused authorization).
    viewer_id       text
        CONSTRAINT playback_access_log_viewer_len CHECK (viewer_id IS NULL OR char_length(viewer_id) <= 128),
    auth_method     text
        CONSTRAINT playback_access_log_auth_method CHECK (auth_method IS NULL OR auth_method IN ('api_key', 'jwt', 'callback')),
    event           text NOT NULL
        CONSTRAINT playback_access_log_event CHECK (event IN (
            'session_created', 'session_denied', 'playlist', 'key', 'key_denied',
            'heartbeat', 'end', 'revoked', 'expired', 'segments')),
    at              timestamptz NOT NULL,
    -- Only on 'segments' rows: how many segment requests the session made in the flush interval.
    segments_served integer,
    ip              inet,
    user_agent      text
        CONSTRAINT playback_access_log_ua_len CHECK (user_agent IS NULL OR char_length(user_agent) <= 256),
    request_id      text
        CONSTRAINT playback_access_log_request_id_len CHECK (request_id IS NULL OR char_length(request_id) <= 64),
    CONSTRAINT playback_access_log_segments CHECK ((event = 'segments') = (segments_served IS NOT NULL)
        AND (segments_served IS NULL OR segments_served > 0))
) PARTITION BY RANGE (at);

CREATE INDEX playback_access_log_asset_idx ON playback_access_log (tenant_id, asset_id, at DESC, id DESC);
CREATE INDEX playback_access_log_session_idx ON playback_access_log (tenant_id, session_hash, at DESC, id DESC);

-- Creates the partition of the UTC calendar month that contains p_month, if it does not exist, and
-- returns true when it created it. Safe to call from any number of replicas at once: a transaction
-- advisory lock serialises them. Partitions are named playback_access_log_pYYYYMM and span
-- [first of the month, first of the next month) in UTC.
-- +goose StatementBegin
CREATE FUNCTION playback_access_log_ensure_partition(p_month date) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    m_start date := date_trunc('month', p_month)::date;
    m_end   date := (date_trunc('month', p_month) + interval '1 month')::date;
    part    text := 'playback_access_log_p' || to_char(m_start, 'YYYYMM');
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cipherframe.playback_access_log.partitions', 0));
    IF to_regclass(quote_ident(part)) IS NOT NULL THEN
        RETURN false;
    END IF;
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF playback_access_log FOR VALUES FROM (%L) TO (%L)',
        part,
        to_char(m_start, 'YYYY-MM-DD') || ' 00:00:00+00',
        to_char(m_end, 'YYYY-MM-DD') || ' 00:00:00+00');
    RETURN true;
END;
$$;
-- +goose StatementEnd

-- Drops every partition whose whole range lies before p_before (its upper bound is at or before
-- it), and returns the names it dropped. NOT CALLED YET: access-log retention is M6-4 (gate P11).
-- It only touches partitions named playback_access_log_pYYYYMM, so nothing else can be dropped by
-- mistake, and it refuses a cutoff that would drop a partition that is not yet fully in the past.
-- +goose StatementBegin
CREATE FUNCTION playback_access_log_drop_partitions_before(p_before date) RETURNS SETOF text
LANGUAGE plpgsql AS $$
DECLARE
    r record;
    upper_bound date;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cipherframe.playback_access_log.partitions', 0));
    IF p_before > (now() AT TIME ZONE 'UTC')::date THEN
        RAISE EXCEPTION 'cutoff is in the future';
    END IF;
    FOR r IN
        SELECT c.relname::text AS name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'playback_access_log'::regclass
          AND c.relname ~ '^playback_access_log_p[0-9]{6}$'
        ORDER BY c.relname
    LOOP
        upper_bound := (to_date(substr(r.name, length('playback_access_log_p') + 1), 'YYYYMM') + interval '1 month')::date;
        IF upper_bound <= p_before THEN
            EXECUTE format('DROP TABLE %I', r.name);
            RETURN NEXT r.name;
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

SELECT playback_access_log_ensure_partition((now() AT TIME ZONE 'UTC')::date);
SELECT playback_access_log_ensure_partition(((now() AT TIME ZONE 'UTC') + interval '1 month')::date);

-- One optional row per tenant. A tenant without a row has every option off, the most private
-- choice (db.DefaultPrivacySettings). Gate P11 (M6) decides the final defaults and adds fields
-- (access-log retention, original-filename storage, asset TTL).
CREATE TABLE privacy_settings (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants (id),
    store_ip         boolean NOT NULL DEFAULT false,
    store_user_agent boolean NOT NULL DEFAULT false,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE privacy_settings;
DROP FUNCTION playback_access_log_drop_partitions_before(date);
DROP FUNCTION playback_access_log_ensure_partition(date);
DROP TABLE playback_access_log;
DROP SEQUENCE playback_access_log_id_seq;
