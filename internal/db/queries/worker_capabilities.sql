-- name: UpsertWorkerCapabilities :exec
-- A worker process says which extra codecs it can encode, at startup and then on every heartbeat.
INSERT INTO worker_capabilities (worker_id, codecs, started_at, last_seen_at)
VALUES (sqlc.arg(worker_id)::uuid, sqlc.arg(codecs)::text[], sqlc.arg(at)::timestamptz, sqlc.arg(at)::timestamptz)
ON CONFLICT (worker_id) DO UPDATE SET codecs = EXCLUDED.codecs, last_seen_at = EXCLUDED.last_seen_at;

-- name: ListRecentWorkerCodecs :many
-- The distinct extra codecs reported by a worker seen since the cutoff.
SELECT DISTINCT c::text AS codec
FROM worker_capabilities, unnest(codecs) AS c
WHERE last_seen_at >= sqlc.arg(cutoff)::timestamptz
ORDER BY 1;

-- name: DeleteStaleWorkerCapabilities :execrows
-- Rows of workers that stopped: a long-gone worker is not a capability.
DELETE FROM worker_capabilities WHERE last_seen_at < sqlc.arg(cutoff)::timestamptz;
