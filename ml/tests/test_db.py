"""Claim, lease and complete against a real Postgres with the real goose migrations.

Needs Docker. Run `pytest -m "not docker"` to skip. CIPHERFRAME_TEST_PG_IMAGE picks the image.
"""

import json
import os
import re
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from cipherframe_ml import tasks, worker
from cipherframe_ml.config import Config
from conftest import validator

pytestmark = pytest.mark.docker

MIGRATIONS = Path(__file__).resolve().parents[2] / "internal" / "db" / "migrations"
KIND = "media.mask_faces"
TENANT = "ten_06gwdaegq9t2h274zqfhnv16ec"


def goose_up(sql: str) -> str:
    return re.split(r"^-- \+goose Down", sql.split("-- +goose Up", 1)[1], flags=re.M)[0]


@pytest.fixture(scope="module")
def dsn():
    try:
        from testcontainers.postgres import PostgresContainer

        pg = PostgresContainer(os.environ.get("CIPHERFRAME_TEST_PG_IMAGE", "postgres:16.15"))
        pg.start()
    except Exception as e:  # no Docker daemon, image pull failure
        pytest.skip(f"Postgres container unavailable: {e}")
    url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    with psycopg.connect(url, autocommit=True) as c:
        for f in sorted(MIGRATIONS.glob("*.sql")):
            c.execute(goose_up(f.read_text()))
    yield url
    pg.stop()


@pytest.fixture
def conn(dsn):
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as c:
        c.execute("DELETE FROM external_tasks")
        yield c


def add_task(conn, payload=None, max_attempts=3, kind=KIND, created="now()") -> uuid.UUID:
    tid = uuid.uuid4()
    envelope = {
        "envelope_version": 1,
        "task_id": str(tid),
        "kind": kind,
        "tenant_id": TENANT,
        "attempt": 1,
        "created_at": "2026-11-14T10:00:00+00:00",
        "trace": {},
        "payload": payload or {"input": "j/in.mp4", "output": "j/out.mp4"},
    }
    conn.execute(
        "INSERT INTO external_tasks (id, kind, envelope, max_attempts, created_at)"
        f" VALUES (%s, %s, %s::jsonb, %s, {created})",
        (tid, kind, json.dumps(envelope), max_attempts),
    )
    return tid


def row(conn, tid):
    return conn.execute("SELECT * FROM external_tasks WHERE id = %s", (tid,)).fetchone()


def expire(conn, tid):
    conn.execute(
        "UPDATE external_tasks SET lease_until = now() - interval '1 second' WHERE id=%s", (tid,)
    )


def test_claim_leases_one_pending_task_of_the_kind(conn):
    other = add_task(conn, kind="ml.embed")
    tid = add_task(conn)
    got = tasks.claim(conn, [KIND], "w1", 30)
    assert got["id"] == tid
    assert got["envelope"]["attempt"] == 1
    assert tasks.claim(conn, [KIND], "w2", 30) is None
    assert row(conn, other)["state"] == "pending"  # other kinds are left alone


def test_claim_is_oldest_first(conn):
    newer = add_task(conn)
    older = add_task(conn, created="now() - interval '1 hour'")
    assert tasks.claim(conn, [KIND], "w", 30)["id"] == older
    assert tasks.claim(conn, [KIND], "w", 30)["id"] == newer


def test_skip_locked_never_hands_out_a_locked_row(dsn, conn):
    first, second = add_task(conn), add_task(conn)
    with psycopg.connect(dsn) as holder:  # a transaction holding the oldest row's lock
        holder.execute("SELECT id FROM external_tasks WHERE id = %s FOR UPDATE", (first,))
        got = tasks.claim(conn, [KIND], "w", 30)
        assert got["id"] == second
        holder.rollback()


def test_heartbeat_extends_only_for_the_owner(conn):
    tid = add_task(conn)
    tasks.claim(conn, [KIND], "w1", 30)
    expire(conn, tid)
    assert not tasks.heartbeat(conn, tid, "w2", 30)
    assert tasks.heartbeat(conn, tid, "w1", 30)
    assert tasks.claim(conn, [KIND], "w2", 30) is None  # lease is live again


def test_complete_writes_a_valid_result_and_clears_the_lease(conn):
    tid = add_task(conn)
    tasks.claim(conn, [KIND], "w1", 30)
    assert not tasks.complete(conn, tid, "w2", {})  # not the owner
    assert tasks.complete(conn, tid, "w1", {"output": {"faces_detected": 2, "frames": 9}})
    task = row(conn, tid)
    assert task["state"] == "succeeded" and task["lease_owner"] is None
    assert task["completed_at"] is not None
    validator("result.schema.json").validate(task["result"])
    validator("kinds/media.mask_faces.output.schema.json").validate(task["result"]["output"])
    assert not tasks.heartbeat(conn, tid, "w1", 30)


def test_fail_records_error_and_retryable_flag(conn):
    tid = add_task(conn)
    tasks.claim(conn, [KIND], "w1", 30)
    assert tasks.fail(conn, tid, "w1", "decode_failed", "no stream", False)
    task = row(conn, tid)
    assert task["state"] == "failed"
    validator("result.schema.json").validate(task["result"])
    assert task["result"]["error"] == {
        "code": "decode_failed",
        "retryable": False,
        "message": "no stream",
    }


def test_expired_lease_is_reclaimed_as_a_new_attempt(conn):
    tid = add_task(conn, max_attempts=3)
    tasks.claim(conn, [KIND], "w1", 30)
    expire(conn, tid)
    got = tasks.claim(conn, [KIND], "w2", 30)
    assert got["id"] == tid and got["envelope"]["attempt"] == 2
    assert not tasks.complete(conn, tid, "w1", {})  # the old owner lost the lease
    assert tasks.complete(conn, tid, "w2", {})


def test_expired_lease_without_attempts_left_is_not_reclaimed(conn):
    tid = add_task(conn, max_attempts=1)
    tasks.claim(conn, [KIND], "w1", 30)
    expire(conn, tid)
    assert tasks.claim(conn, [KIND], "w2", 30) is None  # the Go side fails it with lease_expired


def test_worker_reports_invalid_payload_as_permanent_failure(dsn, conn, tmp_path):
    tid = add_task(conn, payload={"input": "/etc/passwd", "output": "j/out.mp4"})
    cfg = _cfg(dsn, tmp_path)
    worker.serve(cfg, lambda frame: [], once=True)
    task = row(conn, tid)
    result = task["result"]
    assert task["state"] == "failed"
    validator("result.schema.json").validate(result)
    assert result["error"]["code"] == "invalid_payload" and result["error"]["retryable"] is False


def _cfg(dsn, tmp_path) -> Config:
    return Config(dsn, tmp_path, "ffmpeg", Path("unused"), lease_seconds=30, poll_seconds=0.1)


def test_worker_masks_a_clip_end_to_end(dsn, conn, tmp_path, ffmpeg):
    from test_mask import make_clip

    (tmp_path / "j").mkdir()
    make_clip(ffmpeg, tmp_path / "j" / "in.mp4", audio=True)
    tid = add_task(conn)
    cfg = replace(_cfg(dsn, tmp_path), ffmpeg_path=ffmpeg)
    worker.serve(cfg, lambda frame: [(100, 80, 60, 60)], once=True)
    task = row(conn, tid)
    result = task["result"]
    assert task["state"] == "succeeded", result
    validator("result.schema.json").validate(result)
    assert result["output"] == {"faces_detected": 30, "frames": 30}
    assert (tmp_path / "j" / "out.mp4").stat().st_size > 0
    assert not list((tmp_path / "j").glob("*.part"))
