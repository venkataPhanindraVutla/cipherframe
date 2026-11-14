import subprocess

import cv2
import numpy as np
import pytest

from cipherframe_ml.boxes import pad_box
from cipherframe_ml.mask import MaskError, YuNetDetector, mask_frame, mask_video
from cipherframe_ml.model import DEFAULT_MODEL_PATH, verify_model

W, H, FPS = 320, 240, 10


def noisy_frame() -> np.ndarray:
    return np.random.default_rng(1).integers(0, 256, (H, W, 3), dtype=np.uint8)


def test_blur_covers_padded_box_and_nothing_else():
    frame = noisy_frame()
    original = frame.copy()
    box = (100, 80, 40, 40)
    mask_frame(frame, [box])
    x, y, w, h = pad_box(box, W, H)
    assert (w, h) == (60, 60)
    inside = frame[y : y + h, x : x + w].astype(float)
    assert inside.std() < 0.2 * original[y : y + h, x : x + w].std()
    outside = np.ones((H, W), bool)
    outside[y : y + h, x : x + w] = False
    assert (frame[outside] == original[outside]).all()


def test_blur_every_face_and_clamp_at_edges():
    frame = noisy_frame()
    original = frame.copy()
    mask_frame(frame, [(0, 0, 30, 30), (W - 20, H - 20, 60, 60), (10, 150, 20, 20)])
    for x, y, w, h in [(0, 0, 38, 38), (W - 35, H - 35, 35, 35), (5, 145, 30, 30)]:
        assert frame[y : y + h, x : x + w].std() < 0.3 * original[y : y + h, x : x + w].std()
    assert frame.shape == original.shape


def first_n_frames(n, box):
    calls = []

    def detect(frame):
        calls.append(1)
        return [box] if len(calls) <= n else []

    return detect


def make_clip(ffmpeg, path, audio: bool):
    cmd = [
        ffmpeg,
        "-loglevel",
        "error",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"testsrc=size={W}x{H}:rate={FPS}:duration=3",
    ]
    if audio:
        cmd += ["-f", "lavfi", "-i", "sine=duration=3", "-c:a", "aac"]
    subprocess.run([*cmd, "-c:v", "libx264", "-pix_fmt", "yuv420p", str(path)], check=True)  # noqa: S603


def streams(ffmpeg, path) -> str:
    r = subprocess.run([ffmpeg, "-hide_banner", "-i", str(path)], capture_output=True, text=True)  # noqa: S603
    return r.stderr


def read_frames(path) -> list[np.ndarray]:
    cap, out = cv2.VideoCapture(str(path)), []
    while True:
        ok, f = cap.read()
        if not ok:
            return out
        out.append(f)


@pytest.mark.parametrize("audio", [True, False])
def test_pipeline_with_stub_detector(ffmpeg, tmp_path, audio):
    src, dst = tmp_path / "in.mp4", tmp_path / "out.mp4"
    make_clip(ffmpeg, src, audio)
    box = (100, 80, 60, 60)
    # Face detected in frames 0-4 only; hold is 1 s = 10 frames, so blurred through frame 14.
    stats = mask_video(src, dst, first_n_frames(5, box), ffmpeg)
    assert (stats.frames, stats.frames_with_face) == (30, 5)
    meta = streams(ffmpeg, dst)
    assert ("Audio:" in meta) == audio
    assert f"{W}x{H}" in meta
    before, after = read_frames(src), read_frames(dst)
    assert len(after) == 30
    x, y, w, h = pad_box(box, W, H)

    def detail(frames, i):  # high-frequency energy of the region
        gray = cv2.cvtColor(frames[i][y : y + h, x : x + w], cv2.COLOR_BGR2GRAY)
        return cv2.Laplacian(gray, cv2.CV_64F).var()

    for i in (0, 4, 12):  # detected and held frames
        assert detail(after, i) < 0.3 * detail(before, i)
    for i in (16, 29):  # hold expired
        assert detail(after, i) > 0.7 * detail(before, i)


def test_detect_every_runs_the_detector_on_a_stride_and_masks_every_frame(ffmpeg, tmp_path):
    src, dst = tmp_path / "in.mp4", tmp_path / "out.mp4"
    make_clip(ffmpeg, src, audio=False)
    box, calls = (100, 80, 60, 60), []

    def detect(frame):
        calls.append(1)
        return [box]

    stats = mask_video(src, dst, detect, ffmpeg, detect_every=4)
    assert len(calls) == 8  # frames 0, 4, ..., 28 of 30
    assert (stats.frames, stats.frames_with_face) == (30, 30)  # reused detections count
    before, after = read_frames(src), read_frames(dst)
    x, y, w, h = pad_box(box, W, H)

    def detail(frames, i):
        gray = cv2.cvtColor(frames[i][y : y + h, x : x + w], cv2.COLOR_BGR2GRAY)
        return cv2.Laplacian(gray, cv2.CV_64F).var()

    for i in (0, 1, 2, 3, 5, 29):  # detected and skipped frames alike
        assert detail(after, i) < 0.3 * detail(before, i)


def test_unreadable_input_is_a_permanent_failure(ffmpeg, tmp_path):
    bad = tmp_path / "bad.mp4"
    bad.write_bytes(b"not a video")
    with pytest.raises(MaskError) as e:
        mask_video(bad, tmp_path / "out.mp4", lambda f: [], ffmpeg)
    assert (e.value.code, e.value.retryable) == ("decode_failed", False)


def test_missing_ffmpeg_is_a_retryable_failure(ffmpeg, tmp_path):
    src = tmp_path / "in.mp4"
    make_clip(ffmpeg, src, audio=False)
    with pytest.raises(FileNotFoundError):  # worker.handle maps this to a retryable internal_error
        mask_video(src, tmp_path / "out.mp4", lambda f: [], "/nonexistent/ffmpeg")


def test_stop_flag_aborts(ffmpeg, tmp_path):
    src = tmp_path / "in.mp4"
    make_clip(ffmpeg, src, audio=False)
    with pytest.raises(MaskError) as e:
        mask_video(src, tmp_path / "out.mp4", lambda f: [], ffmpeg, should_stop=lambda: True)
    assert e.value.code == "lease_lost"


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not fetched")
def test_real_model_loads_and_finds_no_face_in_noise():
    detect = YuNetDetector(verify_model(DEFAULT_MODEL_PATH))
    assert detect(np.zeros((480, 1280, 3), np.uint8)) == []
