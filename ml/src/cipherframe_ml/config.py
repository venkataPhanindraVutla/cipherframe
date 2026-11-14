"""Configuration from CIPHERFRAME_* environment variables with _FILE variants (ADR 0013)."""

import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .model import DEFAULT_MODEL_PATH


class ConfigError(Exception):
    pass


def read_secret(env: Mapping[str, str], name: str) -> str:
    """Return $name or the contents of the file named by $name_FILE; setting both is an error."""
    value, file = env.get(name), env.get(name + "_FILE")
    if value and file:
        raise ConfigError(f"set only one of {name} and {name}_FILE")
    if file:
        try:
            value = Path(file).read_text().strip()
        except OSError as e:
            raise ConfigError(f"cannot read {name}_FILE: {e.strerror}") from None
    if not value:
        raise ConfigError(f"{name} (or {name}_FILE) is required")
    return value


@dataclass(frozen=True)
class Config:
    database_url: str
    work_dir: Path
    ffmpeg_path: str
    model_path: Path
    lease_seconds: float = 60.0
    poll_seconds: float = 2.0
    detect_every: int = 1

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Config":
        work = env.get("CIPHERFRAME_WORK_DIR") or str(Path(tempfile.gettempdir()) / "cipherframe")
        if not Path(work).is_absolute():
            raise ConfigError("CIPHERFRAME_WORK_DIR must be an absolute path")
        raw = env.get("CIPHERFRAME_ML_DETECT_EVERY") or "1"
        if not raw.isascii() or not raw.isdigit() or int(raw) < 1:
            raise ConfigError("CIPHERFRAME_ML_DETECT_EVERY must be a whole number of at least 1")
        return cls(
            database_url=read_secret(env, "CIPHERFRAME_ML_DATABASE_URL"),
            work_dir=Path(work),
            ffmpeg_path=env.get("CIPHERFRAME_FFMPEG_PATH") or "ffmpeg",
            model_path=Path(env.get("CIPHERFRAME_ML_MODEL_PATH") or DEFAULT_MODEL_PATH),
            detect_every=int(raw),
        )
