# Job contract for external workers

This directory is the language-neutral contract between Cipherframe's Go service and workers written
in other languages, such as the Python ML worker planned for v2.1 (ADR 0010). It is the only thing an
external worker needs to know about Cipherframe's job system. It never touches River's tables.

| File | Purpose |
|---|---|
| `envelope.schema.json` | JSON Schema 2020-12 for the task envelope the Go side writes. |
| `result.schema.json` | JSON Schema 2020-12 for the result a worker writes back. |
| `vectors/valid/*.json` | Documents that must validate. `envelope-*` use the envelope schema, `result-*` the result schema. |
| `vectors/invalid/*.json` | Documents that must be rejected by the schema of the same prefix. |

Both the Go side and any external worker must pass every vector. The Go tests run them with
`github.com/santhosh-tekuri/jsonschema/v6`; a worker's tests should do the same with a validator for
its own language (enable format assertions for `uuid` and `date-time`).

`envelope_version` is `1`. A worker must refuse an envelope with a version it does not know, and
must not write a result with a different version.

## What a task is

A task is one row of the `external_tasks` table:

| Column | Meaning |
|---|---|
| `id` | UUID. Equals `envelope.task_id`. |
| `kind` | Equals `envelope.kind`. Workers claim by kind. |
| `envelope` | The envelope document (`jsonb`). |
| `state` | `pending`, `leased`, `succeeded` or `failed`. |
| `attempts` | Zero-based index of the current attempt. The envelope's `attempt` is `attempts + 1`. |
| `max_attempts` | The task is not leased again once `attempts + 1 >= max_attempts` after a lease expiry. |
| `lease_owner`, `lease_until` | Who holds the task and until when. Set only while `state = 'leased'`. |
| `result` | The result document (`jsonb`), set when the worker completes or fails the task. |
| `created_at`, `updated_at`, `completed_at` | Timestamps. |

The Go service writes the row (and a River job that waits for it) in one transaction. The worker
changes only `state`, `lease_owner`, `lease_until`, `attempts` (on lease reclaim, inside the claim
statement), `result`, `updated_at` and `completed_at`, and only with the statements below. After the
worker records a result, the Go side acts on it: it registers the artifacts of a succeeded task,
puts a task whose failure is retryable back to `pending` (attempt number plus one) while attempts
remain, and sends a non-retryable failure to its dead-letter list.

## Claim protocol

Every statement is a single SQL statement. Use a plain connection; no explicit transaction is needed.
`$n` are bind parameters.

### Claim

`$1` is the text array of kinds this worker handles, `$2` is the worker's lease owner name (unique per
worker process, for example `ml-worker-<hostname>-<pid>`), and `$3` is the lease length in seconds.
It returns zero rows when nothing is claimable and one row when a task was claimed; read the
envelope from the returned row.

```sql
UPDATE external_tasks AS t
SET state       = 'leased',
    lease_owner = $2::text,
    lease_until = now() + make_interval(secs => $3::float8),
    attempts    = t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END,
    envelope    = jsonb_set(t.envelope, '{attempt}',
                      to_jsonb(t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END + 1)),
    updated_at  = now()
WHERE t.id = (
    SELECT c.id FROM external_tasks AS c
    WHERE c.kind = ANY($1::text[])
      AND (c.state = 'pending'
           OR (c.state = 'leased' AND c.lease_until < now() AND c.attempts + 1 < c.max_attempts))
    ORDER BY c.created_at, c.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING t.*;
```

`FOR UPDATE SKIP LOCKED` lets many workers claim at once without blocking or double-claiming. A
leased row whose lease has expired is claimable again; that counts as a new attempt, so a task that
keeps crashing its workers runs out of attempts instead of looping forever. When it has none left,
the Go side fails it with the retryable code `lease_expired`.

### Heartbeat

Call this before the lease runs out, for example every third of the lease length. It extends the
lease only while this worker still holds it. Zero rows updated means the lease was lost (it expired
and another worker claimed the task): stop work and do not write a result.

```sql
UPDATE external_tasks
SET lease_until = now() + make_interval(secs => $3::float8),
    updated_at  = now()
WHERE id = $1 AND state = 'leased' AND lease_owner = $2::text;
```

### Complete

`$3` is a result document with `"status": "succeeded"` that validates against `result.schema.json`.
Zero rows updated means the lease was lost; the result is discarded.

```sql
UPDATE external_tasks
SET state        = 'succeeded',
    result       = $3::jsonb,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = now()
WHERE id = $1 AND state = 'leased' AND lease_owner = $2::text;
```

### Fail

`$3` is a result document with `"status": "failed"` and an `error` object. Set `retryable` to `true`
when repeating the task could succeed (a model server was briefly down) and to `false` when it
cannot (the media has no decodable stream). Zero rows updated means the lease was lost.

```sql
UPDATE external_tasks
SET state        = 'failed',
    result       = $3::jsonb,
    lease_owner  = NULL,
    lease_until  = NULL,
    updated_at   = now(),
    completed_at = now()
WHERE id = $1 AND state = 'leased' AND lease_owner = $2::text;
```

A worker that cannot finish and does nothing simply lets its lease expire.

## Derived artifacts

Everything a worker writes to storage must be listed in `artifacts` of a succeeded result (kind,
storage key, SHA-256 of the stored bytes, size, and the model that produced it). The Go side
registers each artifact so that deletion can enumerate and purge it (invariant I6). A derived object
that is not in the result is invisible to deletion, so a worker must not write one.

## What must never be in an envelope or a result

Secrets, tokens, signed URLs, key material and source object keys (invariants I4 and I9). A task
carries identifiers and kind-specific parameters. A worker obtains its input through its own storage
credentials, never from the envelope. `error.message` is for operators; keep it free of any of the
above and of user content.

## Database role for external workers

This is documentation only; the role is not created by Cipherframe's migrations. Run each external
worker with a dedicated database role whose grants are limited to the hand-off table:

```sql
CREATE ROLE cipherframe_worker LOGIN PASSWORD '...';   -- set a real secret outside version control
GRANT CONNECT ON DATABASE cipherframe TO cipherframe_worker;
GRANT USAGE ON SCHEMA public TO cipherframe_worker;
GRANT SELECT ON external_tasks TO cipherframe_worker;
GRANT UPDATE (state, attempts, lease_owner, lease_until, envelope, result, updated_at, completed_at)
    ON external_tasks TO cipherframe_worker;
```

The role gets no access to any other table, in particular not to River's tables, to `assets`, to
`api_keys` or to key material. It cannot insert or delete tasks. Note the limit of this protection:
the role can read the envelope of every task of any kind, across tenants, and can write any task's
result. It is a boundary between the worker and the rest of the database, not between tenants.
`UPDATE` on the `envelope` column is needed only because the claim statement records the attempt
number in it.
