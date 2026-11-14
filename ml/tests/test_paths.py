import pytest

from cipherframe_ml.paths import PathError, resolve_in_workdir


def test_accepts_relative_path(tmp_path):
    (tmp_path / "job").mkdir()
    assert resolve_in_workdir(tmp_path, "job/a.mp4") == tmp_path.resolve() / "job" / "a.mp4"


@pytest.mark.parametrize("bad", ["", "/etc/passwd", "../x", "a/../../x", "a/..", "a\\b", "a\x00b"])
def test_rejects_bad_paths(tmp_path, bad):
    with pytest.raises(PathError):
        resolve_in_workdir(tmp_path, bad)


def test_rejects_non_string(tmp_path):
    with pytest.raises(PathError):
        resolve_in_workdir(tmp_path, None)  # type: ignore[arg-type]


def test_rejects_symlink_escaping_workdir(tmp_path):
    work, outside = tmp_path / "work", tmp_path / "outside"
    work.mkdir()
    outside.mkdir()
    (outside / "secret.mp4").write_bytes(b"x")
    (work / "link").symlink_to(outside)
    (work / "file-link").symlink_to(outside / "secret.mp4")
    with pytest.raises(PathError):
        resolve_in_workdir(work, "link/secret.mp4")
    with pytest.raises(PathError):
        resolve_in_workdir(work, "file-link")


def test_allows_symlink_inside_workdir(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    assert resolve_in_workdir(tmp_path, "alias/a.mp4") == tmp_path.resolve() / "real" / "a.mp4"
