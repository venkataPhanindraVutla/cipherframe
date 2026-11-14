"""Resolve payload paths inside the shared work directory (ADR 0027: plaintext stays local)."""

from pathlib import Path, PurePosixPath


class PathError(ValueError):
    pass


def resolve_in_workdir(work_dir: Path, rel: str) -> Path:
    """Return work_dir/rel, rejecting absolute paths, '..', and symlinks that leave work_dir."""
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel:
        raise PathError("path must be a non-empty relative string")
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts:
        raise PathError("path must be relative and must not contain '..'")
    root = work_dir.resolve(strict=True)
    full = (root / p).resolve()  # follows symlinks, including ones in the middle of the path
    if not full.is_relative_to(root):
        raise PathError("path escapes the work directory")
    return full
