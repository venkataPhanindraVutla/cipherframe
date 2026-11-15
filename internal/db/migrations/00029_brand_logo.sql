-- +goose Up
-- M7-4: per-tenant brand logo burned in at transcode (ADR 0049).
--
--  * tenant_logo_versions: one row per stored logo image. A version is immutable: a new upload is a
--    new row and a new object under the tenant's branding prefix; the bytes are never replaced.
--  * tenant_logos: the tenant's current logo: which version, where it sits, how opaque it is, and
--    whether new assets get it. A row exists only while the tenant has a logo.
--  * asset_logo_pins: what an asset was transcoded with. The first processing job of an asset (the
--    original or the masked variant, whichever starts first) writes the row from the tenant's
--    current logo, and every later job and retry of that asset reads it back, so one asset never
--    mixes two logos. version_id is NULL when the asset has no logo. There is no foreign key to
--    tenant_logo_versions on purpose: a finished asset's row keeps the hash and placement it was
--    made with after the version itself is removed.
CREATE TABLE tenant_logo_versions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    sha256     bytea NOT NULL CONSTRAINT tenant_logo_versions_sha256_len CHECK (octet_length(sha256) = 32),
    size_bytes integer NOT NULL CONSTRAINT tenant_logo_versions_size CHECK (size_bytes BETWEEN 1 AND 262144),
    width      integer NOT NULL CONSTRAINT tenant_logo_versions_width CHECK (width BETWEEN 16 AND 1024),
    height     integer NOT NULL CONSTRAINT tenant_logo_versions_height CHECK (height BETWEEN 16 AND 1024),
    created_at timestamptz NOT NULL
);

CREATE INDEX tenant_logo_versions_tenant_idx ON tenant_logo_versions (tenant_id);

CREATE TABLE tenant_logos (
    tenant_id       uuid PRIMARY KEY REFERENCES tenants (id),
    version_id      uuid NOT NULL REFERENCES tenant_logo_versions (id),
    corner          text NOT NULL
        CONSTRAINT tenant_logos_corner_allowed CHECK (corner IN ('top_left', 'top_right', 'bottom_left', 'bottom_right')),
    opacity_percent integer NOT NULL CONSTRAINT tenant_logos_opacity_range CHECK (opacity_percent BETWEEN 10 AND 100),
    enabled         boolean NOT NULL,
    updated_at      timestamptz NOT NULL
);

CREATE TABLE asset_logo_pins (
    asset_id        uuid PRIMARY KEY REFERENCES assets (id),
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    version_id      uuid,
    sha256          bytea,
    corner          text,
    opacity_percent integer,
    pinned_at       timestamptz NOT NULL,
    CONSTRAINT asset_logo_pins_all_or_none CHECK (
        (version_id IS NULL AND sha256 IS NULL AND corner IS NULL AND opacity_percent IS NULL)
        OR (version_id IS NOT NULL AND octet_length(sha256) = 32 AND corner IN ('top_left', 'top_right', 'bottom_left', 'bottom_right')
            AND opacity_percent BETWEEN 10 AND 100))
);

CREATE INDEX asset_logo_pins_version_idx ON asset_logo_pins (version_id) WHERE version_id IS NOT NULL;

-- +goose Down
DROP TABLE asset_logo_pins;
DROP TABLE tenant_logos;
DROP TABLE tenant_logo_versions;
