"""The external_tasks claim protocol (spec/jobs/README.md), written as plain SQL."""

import json
from typing import Any

import psycopg

ENVELOPE_VERSION = 1

CLAIM = """
UPDATE external_tasks AS t
SET state       = 'leased',
    lease_owner = %(owner)s::text,
    lease_until = now() + make_interval(secs => %(secs)s::float8),
    attempts    = t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END,
    envelope    = jsonb_set(t.envelope, '{attempt}',
                      to_jsonb(t.attempts + CASE WHEN t.state = 'leased' THEN 1 ELSE 0 END + 1)),
    updated_at  = now()
WHERE t.id = (
    SELECT c.id FROM external_tasks AS c
    WHERE c.kind = ANY(%(kinds)s::text[])
      AND (c.state = 'pending'
           OR (c.state = 'leased' AND c.lease_until < now() AND c.attempts + 1 < c.max_attempts))
    ORDER BY c.created_at, c.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING t.id, t.kind, t.envelope
"""

HEARTBEAT = """
UPDATE external_tasks
SET lease_until = now() + make_interval(secs => %(secs)s::float8), updated_at = now()
WHERE id = %(id)s AND state = 'leased' AND lease_owner = %(owner)s::text
"""

_FINISH = """
UPDATE external_tasks
SET state = %(state)s, result = %(result)s::jsonb, lease_owner = NULL, lease_until = NULL,
    updated_at = now(), completed_at = now()
WHERE id = %(id)s AND state = 'leased' AND lease_owner = %(owner)s::text
"""


def claim(conn: psycopg.Connection, kinds: list[str], owner: str, lease_s: float) -> dict | None:
    """Claim one task, or return None. Returns {"id", "kind", "envelope"}."""
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(CLAIM, {"owner": owner, "secs": lease_s, "kinds": kinds})
        return cur.fetchone()


def heartbeat(conn: psycopg.Connection, task_id: Any, owner: str, lease_s: float) -> bool:
    """Extend the lease. False means the lease was lost: stop and write nothing."""
    cur = conn.execute(HEARTBEAT, {"id": task_id, "owner": owner, "secs": lease_s})
    return cur.rowcount == 1


def _finish(conn: psycopg.Connection, state: str, task_id: Any, owner: str, result: dict) -> bool:
    params = {"state": state, "id": task_id, "owner": owner, "result": json.dumps(result)}
    return conn.execute(_FINISH, params).rowcount == 1


def complete(conn: psycopg.Connection, task_id: Any, owner: str, payload: dict) -> bool:
    result = {
        "envelope_version": ENVELOPE_VERSION,
        "task_id": str(task_id),
        "status": "succeeded",
        **payload,
    }
    return _finish(conn, "succeeded", task_id, owner, result)


def fail(
    conn: psycopg.Connection, task_id: Any, owner: str, code: str, message: str, retryable: bool
) -> bool:
    result = {
        "envelope_version": ENVELOPE_VERSION,
        "task_id": str(task_id),
        "status": "failed",
        "error": {"code": code, "retryable": retryable, "message": message[:1024]},
    }
    return _finish(conn, "failed", task_id, owner, result)
