-- name: ListContentKeysNotOnKEK :many
-- Rows whose KEK differs from the given one (the target of a re-wrap), in id order. Keyset
-- pagination on the UUIDv7 id: pass a NULL after_id for the first page.
SELECT * FROM content_keys
WHERE NOT (provider = sqlc.arg(provider)::text
       AND kek_key_id = sqlc.arg(kek_key_id)::text
       AND kek_version = sqlc.arg(kek_version)::text)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::integer;

-- name: CountContentKeysNotOnKEK :one
SELECT count(*) FROM content_keys
WHERE NOT (provider = sqlc.arg(provider)::text
       AND kek_key_id = sqlc.arg(kek_key_id)::text
       AND kek_version = sqlc.arg(kek_version)::text);

-- name: CountContentKeysByKEK :many
-- How many content keys each KEK version wraps. No key material.
SELECT provider, kek_key_id, kek_version, count(*) AS keys
FROM content_keys
GROUP BY provider, kek_key_id, kek_version
ORDER BY provider, kek_key_id, kek_version;
