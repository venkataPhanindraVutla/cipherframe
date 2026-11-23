-- +goose Up
-- M10-4: content-key re-key (ADR 0068). key_generation counts how often the asset's content keys were
-- replaced. Generation 0 is where every asset has always lived. After a re-key the encrypted objects
-- (media segments and media playlists) of every variant sit under a "k<generation>/" directory of the
-- variant's HLS prefix, and a playback session is bound to the generation it started on.
ALTER TABLE assets
    ADD COLUMN key_generation integer NOT NULL DEFAULT 0
        CONSTRAINT assets_key_generation_nonneg CHECK (key_generation >= 0);

-- +goose Down
ALTER TABLE assets DROP COLUMN key_generation;
