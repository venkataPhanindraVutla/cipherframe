"""The media.mask_faces worker: claim, heartbeat, mask, write the result."""

import logging
import os
import socket
import threading
import time
from pathlib import Path

import psycopg

from . import tasks
from .config import Config
from .mask import Detector, MaskError, mask_video
from .paths import PathError, resolve_in_workdir

KIND = "media.mask_faces"
log = logging.getLogger("cipherframe_ml")


def lease_owner() -> str:
    return f"ml-worker-{socket.gethostname()}-{os.getpid()}"


class Heartbeat:
    """Extends the lease on its own connection every third of the lease until stopped or lost."""

    def __init__(self, dsn: str, task_id, owner: str, lease_s: float):
        self.lost = threading.Event()
        self._stop = threading.Event()
        self._args = (dsn, task_id, owner, lease_s)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        dsn, task_id, owner, lease_s = self._args
        try:
            with psycopg.connect(dsn, autocommit=True) as conn:
                while not self._stop.wait(lease_s / 3):
                    if not tasks.heartbeat(conn, task_id, owner, lease_s):
                        self.lost.set()
                        return
        except psycopg.Error:
            log.exception("heartbeat connection failed; the lease will expire")
            self.lost.set()


def run_task(cfg: Config, envelope: dict, detect: Detector, should_stop) -> dict:
    """Do the work of one task. Returns the result fields, or raises MaskError."""
    if envelope.get("envelope_version") != tasks.ENVELOPE_VERSION:
        raise MaskError("unsupported_envelope", "unknown envelope_version", False)
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"input", "output"}:
        raise MaskError("invalid_payload", "payload must be {input, output}", False)
    try:
        src = resolve_in_workdir(cfg.work_dir, payload["input"])
        dst = resolve_in_workdir(cfg.work_dir, payload["output"])
    except PathError as e:
        raise MaskError("invalid_payload", str(e), False) from None
    if not src.is_file():
        raise MaskError("input_not_found", "input file does not exist", False)
    if src == dst or not dst.parent.is_dir():
        raise MaskError(
            "invalid_payload", "output must be a new file in an existing directory", False
        )
    part = Path(f"{dst}.part")
    try:
        stats = mask_video(src, part, detect, cfg.ffmpeg_path, should_stop, cfg.detect_every)
        part.replace(dst)
    finally:
        part.unlink(missing_ok=True)
    return {"output": {"faces_detected": stats.frames_with_face, "frames": stats.frames}}


def handle(conn: psycopg.Connection, cfg: Config, task: dict, owner: str, detect: Detector) -> None:
    task_id = task["id"]
    with Heartbeat(cfg.database_url, task_id, owner, cfg.lease_seconds) as hb:
        try:
            result = run_task(cfg, task["envelope"], detect, hb.lost.is_set)
            error = None
        except MaskError as e:
            result, error = None, e
        except Exception as e:  # unexpected: a repeat may succeed
            log.exception("task %s crashed", task_id)
            result, error = None, MaskError("internal_error", type(e).__name__, True)
        if hb.lost.is_set():
            log.warning("task %s: lease lost, result discarded", task_id)
            return
    if error is None:
        written = tasks.complete(conn, task_id, owner, result)
    else:
        written = tasks.fail(conn, task_id, owner, error.code, str(error), error.retryable)
    if not written:
        log.warning("task %s: lease lost before the result was written", task_id)


def serve(cfg: Config, detect: Detector, once: bool = False) -> None:
    owner = lease_owner()
    with psycopg.connect(cfg.database_url, autocommit=True) as conn:
        while True:
            task = tasks.claim(conn, [KIND], owner, cfg.lease_seconds)
            if task:
                log.info("claimed task %s", task["id"])
                handle(conn, cfg, task, owner, detect)
            elif once:
                return
            else:
                time.sleep(cfg.poll_seconds)
