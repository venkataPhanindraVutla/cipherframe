-- +goose Up
-- M6-2: verified deletion (ADR 0040, ADR 0042).
--
-- A new lifecycle state, 'deleting': the asset has been asked to go and the asset.delete job is
-- working. Playback, new sessions, uploads and the pipeline refuse an asset in this state. The job
-- ends it in 'deleted', which keeps the row as a tombstone (the deletion record, M6-3, refers to it).
--
--  * deletion_requested_at and deletion_reason are set together with 'deleting' and stay on the
--    tombstone. The reason is 'requested' (an API call) or 'retention' (a time-to-live ran out).
--  * deleted_at is set when the purge finished and verified storage is empty.
--  * A tombstone keeps no source object key and no object-store upload ID.

ALTER TABLE assets
    ADD COLUMN deletion_requested_at timestamptz,
    ADD COLUMN deletion_reason text
        CONSTRAINT assets_deletion_reason_allowed CHECK (deletion_reason IN ('requested', 'retention')),
    ADD COLUMN deleted_at timestamptz;

-- 'deleted' was never reached before M6; backfill defensively so the new constraint holds.
UPDATE assets SET deletion_requested_at = updated_at, deletion_reason = 'requested', deleted_at = updated_at
WHERE state = 'deleted';

ALTER TABLE assets
    DROP CONSTRAINT assets_state_allowed,
    ADD CONSTRAINT assets_state_allowed CHECK (
        state IN ('created', 'uploading', 'committed', 'processing', 'ready', 'failed', 'deleting', 'deleted')
    ),
    ADD CONSTRAINT assets_deletion_columns CHECK (
        (state IN ('deleting', 'deleted')) = (deletion_requested_at IS NOT NULL AND deletion_reason IS NOT NULL)
        AND ((state = 'deleted') = (deleted_at IS NOT NULL))
    );

-- +goose Down
UPDATE assets SET state = 'deleted', deleted_at = COALESCE(deleted_at, updated_at) WHERE state = 'deleting';
ALTER TABLE assets
    DROP CONSTRAINT assets_deletion_columns,
    DROP CONSTRAINT assets_state_allowed,
    ADD CONSTRAINT assets_state_allowed CHECK (
        state IN ('created', 'uploading', 'committed', 'processing', 'ready', 'failed', 'deleted')
    ),
    DROP COLUMN deleted_at,
    DROP COLUMN deletion_reason,
    DROP COLUMN deletion_requested_at;
