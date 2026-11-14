-- name: CreateAsset :one
-- The client must belong to the tenant; otherwise no row is inserted.
INSERT INTO assets (id, tenant_id, created_by_client_id, state)
SELECT sqlc.arg(id)::uuid, c.tenant_id, c.id, sqlc.arg(state)::text
FROM clients c
WHERE c.id = sqlc.arg(client_id)::uuid AND c.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets
WHERE tenant_id = $1 AND id = $2;

-- name: CreateUploadAsset :one
-- The client must belong to the tenant; otherwise no row is inserted.
INSERT INTO assets (
    id, tenant_id, created_by_client_id, state, size_bytes, content_type, upload_method,
    source_key, s3_upload_id, upload_expires_at, mask_faces
)
SELECT sqlc.arg(id)::uuid, c.tenant_id, c.id, 'created', sqlc.arg(size_bytes)::bigint,
       sqlc.narg(content_type)::text, sqlc.arg(upload_method)::text, sqlc.arg(source_key)::text,
       sqlc.narg(s3_upload_id)::text, sqlc.arg(upload_expires_at)::timestamptz,
       sqlc.arg(mask_faces)::boolean
FROM clients c
WHERE c.id = sqlc.arg(client_id)::uuid AND c.tenant_id = sqlc.arg(tenant_id)::uuid
RETURNING *;

-- name: LockAsset :one
-- Serialises writers of one asset for the length of the transaction.
SELECT * FROM assets
WHERE tenant_id = $1 AND id = $2
FOR UPDATE;

-- name: ListAssetsPage :many
-- Keyset pagination on the UUIDv7 id, which is creation-ordered. Deleted assets are not listed.
SELECT * FROM assets
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND state <> 'deleted'
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::integer;

-- name: TransitionAsset :one
-- Compare-and-set: the row changes only while it is still in from_state. The failure code is
-- recorded only by a transition to 'failed'.
UPDATE assets SET
    state                 = sqlc.arg(to_state)::text,
    updated_at            = sqlc.arg(at)::timestamptz,
    committed_at          = CASE WHEN sqlc.arg(to_state)::text = 'committed' THEN sqlc.arg(at)::timestamptz ELSE committed_at END,
    processing_started_at = CASE WHEN sqlc.arg(to_state)::text = 'processing' THEN sqlc.arg(at)::timestamptz ELSE processing_started_at END,
    ready_at              = CASE WHEN sqlc.arg(to_state)::text = 'ready' THEN sqlc.arg(at)::timestamptz ELSE ready_at END,
    failed_at             = CASE WHEN sqlc.arg(to_state)::text = 'failed' THEN sqlc.arg(at)::timestamptz ELSE failed_at END,
    failure_code          = CASE WHEN sqlc.arg(to_state)::text = 'failed' THEN sqlc.narg(failure_code)::text ELSE failure_code END
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND state = sqlc.arg(from_state)::text
RETURNING *;

-- name: StartTusUpload :one
-- Records the object store's multipart upload ID and moves created -> uploading, once. A second
-- call finds the asset no longer in 'created' (or already holding an upload ID) and changes nothing.
UPDATE assets SET state = 'uploading', s3_upload_id = sqlc.arg(s3_upload_id)::text, updated_at = sqlc.arg(at)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND state = 'created'
  AND upload_method = 'tus'
  AND s3_upload_id IS NULL
RETURNING *;

-- name: InsertUploadToken :exec
INSERT INTO upload_tokens (token_hash, asset_id, tenant_id, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetUploadGrant :one
SELECT sqlc.embed(a), t.expires_at AS token_expires_at
FROM upload_tokens t
JOIN assets a ON a.id = t.asset_id AND a.tenant_id = t.tenant_id
WHERE t.token_hash = $1;

-- name: DeleteUploadTokens :exec
DELETE FROM upload_tokens WHERE asset_id = $1;

-- name: UpsertUploadPart :exec
INSERT INTO upload_parts (asset_id, part_number, etag, size_bytes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (asset_id, part_number)
DO UPDATE SET etag = EXCLUDED.etag, size_bytes = EXCLUDED.size_bytes, created_at = now();

-- name: ListUploadParts :many
SELECT * FROM upload_parts WHERE asset_id = $1 ORDER BY part_number;

-- name: SumOtherUploadPartSizes :one
SELECT COALESCE(SUM(size_bytes), 0)::bigint AS total FROM upload_parts
WHERE asset_id = $1 AND part_number <> $2;

-- name: DeleteUploadParts :exec
DELETE FROM upload_parts WHERE asset_id = $1;

-- name: RecordAssetSource :execrows
-- Stores what the worker measured while streaming the source. Only while the asset is processing.
UPDATE assets SET
    source_sha256     = sqlc.arg(source_sha256)::bytea,
    source_size_bytes = sqlc.arg(source_size_bytes)::bigint,
    updated_at        = sqlc.arg(at)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND state = 'processing';

-- name: SetAssetProgress :execrows
-- A hint for clients; it never moves backwards (ResetAssetProgress starts a retry from zero) and is
-- written only while processing.
UPDATE assets SET progress = sqlc.arg(progress)::smallint
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND state = 'processing'
  AND progress < sqlc.arg(progress)::smallint;

-- name: ResetAssetProgress :exec
UPDATE assets SET progress = 0
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)::uuid AND state = 'processing';

-- name: CompleteAssetProcessing :one
-- Compare-and-set processing -> ready with the results of the pipeline.
UPDATE assets SET
    state       = 'ready',
    ready_at    = sqlc.arg(at)::timestamptz,
    updated_at  = sqlc.arg(at)::timestamptz,
    duration_ms = sqlc.arg(duration_ms)::bigint,
    renditions  = sqlc.arg(renditions)::jsonb,
    progress    = 100,
    -- A masking asset's masked variant is built after the original is ready (ADR 0036).
    masking_state = CASE WHEN mask_faces THEN 'pending' ELSE masking_state END
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND state = 'processing'
RETURNING *;

-- name: SetAssetMasking :one
-- Records the state of the masked variant and the number of faces the masker found (NULL while
-- unknown). Only for an asset created with mask_faces.
UPDATE assets SET
    masking_state  = sqlc.arg(masking_state)::text,
    faces_detected = sqlc.narg(faces_detected)::integer,
    updated_at     = sqlc.arg(at)::timestamptz
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND id = sqlc.arg(id)::uuid
  AND mask_faces
RETURNING *;
