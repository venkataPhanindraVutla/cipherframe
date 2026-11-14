-- +goose Up
-- M6-4: retention (ADR 0040, ADR 0042).
--
--  * assets.expires_at is when the retention job deletes the asset (reason 'retention'); NULL means
--    never, which is the default: assets are kept until deleted. It is set at creation, from the
--    request or from the tenant's default, and can be changed or cleared later.
--  * privacy_settings.asset_ttl_seconds is the tenant's default time-to-live, applied to assets
--    created after it is set (an asset's expires_at is fixed when it is created). NULL means none.
--  * playback_events gets an index on its age, for the retention delete (the access log is
--    partitioned by month, so its retention drops whole partitions first).
--  * The two access-log partition functions become SECURITY DEFINER, so any role the service runs as
--    can create and drop partitions: the function owner (the role that ran the migrations) owns
--    every partition and the functions only touch tables named playback_access_log_pYYYYMM. The
--    search_path of the migrating session is pinned into the function.
ALTER TABLE assets ADD COLUMN expires_at timestamptz;

CREATE INDEX assets_expires_at_idx ON assets (expires_at, id)
    WHERE expires_at IS NOT NULL AND state NOT IN ('deleting', 'deleted');

ALTER TABLE privacy_settings
    ADD COLUMN asset_ttl_seconds integer
        CONSTRAINT privacy_settings_asset_ttl_range CHECK (asset_ttl_seconds IS NULL OR asset_ttl_seconds BETWEEN 60 AND 315360000);

CREATE INDEX playback_events_at_idx ON playback_events (at);

ALTER FUNCTION playback_access_log_ensure_partition(date) SECURITY DEFINER SET search_path FROM CURRENT;
ALTER FUNCTION playback_access_log_drop_partitions_before(date) SECURITY DEFINER SET search_path FROM CURRENT;

-- +goose Down
ALTER FUNCTION playback_access_log_drop_partitions_before(date) SECURITY INVOKER RESET search_path;
ALTER FUNCTION playback_access_log_ensure_partition(date) SECURITY INVOKER RESET search_path;
DROP INDEX playback_events_at_idx;
ALTER TABLE privacy_settings DROP COLUMN asset_ttl_seconds;
DROP INDEX assets_expires_at_idx;
ALTER TABLE assets DROP COLUMN expires_at;
