"""Decode, detect faces, blur every face, and re-encode with the source audio copied (ADR 0036)."""

import json
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

from .boxes import Box, Holder, pad_box, scale_box

DETECT_WIDTH = 640
SCORE_THRESHOLD = 0.6
BLOCK = 8  # pixelation block size in pixels

# HDR sources are converted to 8-bit BT.709 SDR before OpenCV decodes them: OpenCV knows nothing of
# transfer curves, so frames read from a PQ or HLG file are washed out, and the masked variant would
# be too. The filters are the ones of internal/media/color.go; keep them in step.
HDR_TRANSFERS = frozenset({"smpte2084", "arib-std-b67"})
_TONEMAP = (
    "zscale=t=linear:npl=100{hints},format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,"
    "zscale=t=bt709:m=bt709:r=tv,format=yuv420p"
)
_GAMUT = "zscale=p=bt709:t=bt709:m=bt709:r=tv,format=yuv420p"
_UNSET = ("", "unknown", "unspecified", "reserved")

Detector = Callable[[np.ndarray], list[Box]]  # BGR frame -> unpadded boxes in frame pixels


class MaskError(Exception):
    def __init__(self, code: str, message: str, retryable: bool):
        super().__init__(message)
        self.code, self.retryable = code, retryable


@dataclass
class MaskStats:
    frames: int
    frames_with_face: int


class YuNetDetector:
    def __init__(self, model_path: Path):
        self._net = cv2.FaceDetectorYN.create(
            str(model_path), "", (DETECT_WIDTH, 360), SCORE_THRESHOLD
        )

    def __call__(self, frame: np.ndarray) -> list[Box]:
        h, w = frame.shape[:2]
        factor = w / DETECT_WIDTH if w > DETECT_WIDTH else 1.0
        small = (
            cv2.resize(frame, (round(w / factor), round(h / factor))) if factor != 1.0 else frame
        )
        self._net.setInputSize((small.shape[1], small.shape[0]))
        _, faces = self._net.detect(small)
        if faces is None:
            return []
        return [tuple(round(v) for v in scale_box(f[:4], factor)) for f in faces]  # type: ignore[misc]


def blur_region(frame: np.ndarray, box: Box) -> None:
    """Pixelate then Gaussian-blur the box in place. The box must already be clamped."""
    x, y, w, h = box
    if w < 1 or h < 1:
        return
    roi = frame[y : y + h, x : x + w]
    small = cv2.resize(roi, (max(1, w // BLOCK), max(1, h // BLOCK)), interpolation=cv2.INTER_AREA)
    roi[:] = cv2.resize(small, (w, h), interpolation=cv2.INTER_NEAREST)
    k = max(3, (min(w, h) // 4) | 1)
    roi[:] = cv2.GaussianBlur(roi, (k, k), 0)


def mask_frame(frame: np.ndarray, boxes: list[Box]) -> None:
    h, w = frame.shape[:2]
    for b in boxes:
        blur_region(frame, pad_box(b, w, h))


def sdr_filter(transfer: str, primaries: str, space: str) -> str | None:
    """The ffmpeg filter that turns a source with these colour tags into BT.709 SDR, or None."""
    if transfer in HDR_TRANSFERS:
        # Phones tag everything; for a file that does not, assume the BT.2020 that HDR is made in.
        hints = (":pin=bt2020" if primaries in _UNSET else "") + (
            ":min=bt2020nc" if space in _UNSET else ""
        )
        return _TONEMAP.format(hints=hints)
    return _GAMUT if primaries == "bt2020" else None


def probe_sdr_filter(ffprobe: str, src: Path) -> str | None:
    cmd = [
        ffprobe, "-hide_banner", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=color_transfer,color_primaries,color_space",
        "-of", "json", f"file:{src}",
    ]  # fmt: skip
    r = subprocess.run(cmd, capture_output=True, check=False)  # noqa: S603
    if r.returncode != 0:
        raise MaskError("decode_failed", "input could not be probed", False)
    streams = json.loads(r.stdout or b"{}").get("streams") or [{}]
    s = streams[0]
    return sdr_filter(
        s.get("color_transfer", ""), s.get("color_primaries", ""), s.get("color_space", "")
    )


def _sdr_copy_cmd(ffmpeg: str, src: Path, dst: Path, vf: str) -> list[str]:
    return [
        ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-nostdin",
        "-i", f"file:{src}", "-map", "0:v:0", "-an", "-vf", vf,
        "-c:v", "libx264", "-preset", "ultrafast", "-crf", "12", "-pix_fmt", "yuv420p",
        "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
        "-color_range", "tv",
        "-f", "mp4", f"file:{dst}",
    ]  # fmt: skip


def _ffmpeg_cmd(ffmpeg: str, src: Path, dst: Path, w: int, h: int, fps: float) -> list[str]:
    return [
        ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-nostdin",
        "-f", "rawvideo", "-pix_fmt", "bgr24", "-s", f"{w}x{h}", "-framerate", f"{fps:.6f}",
        "-i", "pipe:0",
        "-i", f"file:{src}",
        "-map", "0:v:0", "-map", "1:a?",
        "-c:v", "libx264", "-preset", "ultrafast", "-crf", "12", "-pix_fmt", "yuv420p",
        "-c:a", "copy",
        "-movflags", "+faststart", "-f", "mp4", f"file:{dst}",
    ]  # fmt: skip


def mask_video(
    src: Path,
    dst: Path,
    detect: Detector,
    ffmpeg: str = "ffmpeg",
    should_stop: Callable[[], bool] = lambda: False,
    detect_every: int = 1,
    ffprobe: str | None = None,
) -> MaskStats:
    """With ffprobe, an HDR or wide-gamut source is converted to BT.709 SDR before it is masked."""
    vf = probe_sdr_filter(ffprobe, src) if ffprobe else None
    if vf is None:
        return _mask_video(src, src, dst, detect, ffmpeg, should_stop, detect_every)
    sdr = Path(f"{dst}.sdr.mp4")
    try:
        r = subprocess.run(  # noqa: S603
            _sdr_copy_cmd(ffmpeg, src, sdr, vf), capture_output=True, check=False
        )
        if r.returncode != 0:
            tail = r.stderr[-500:].decode("utf-8", "replace")
            raise MaskError("decode_failed", f"colour conversion failed: {tail}", False)
        return _mask_video(sdr, src, dst, detect, ffmpeg, should_stop, detect_every)
    finally:
        sdr.unlink(missing_ok=True)


def _mask_video(
    src: Path,
    audio_src: Path,
    dst: Path,
    detect: Detector,
    ffmpeg: str,
    should_stop: Callable[[], bool],
    detect_every: int,
) -> MaskStats:
    cap = cv2.VideoCapture(str(src))
    try:
        ok, frame = cap.read() if cap.isOpened() else (False, None)
        if not ok:
            raise MaskError("decode_failed", "input has no decodable video stream", False)
        h, w = frame.shape[:2]
        fps = cap.get(cv2.CAP_PROP_FPS)
        if not (1.0 <= fps <= 240.0):
            fps = 30.0  # shortcut: unknown fps falls back to 30, upgrade if sources need ffprobe
        holder = Holder(fps)
        frames = with_face = 0
        detected: list[Box] = []
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(  # noqa: S603
                _ffmpeg_cmd(ffmpeg, audio_src, dst, w, h, fps),
                stdin=subprocess.PIPE, stderr=err,
            )  # fmt: skip
            try:
                while ok:
                    if should_stop():
                        raise MaskError("lease_lost", "lease lost", True)
                    if frames % detect_every == 0:  # in between, the last detection is reused
                        detected = detect(frame)
                    with_face += bool(detected)
                    mask_frame(frame, holder.update(detected))
                    proc.stdin.write(frame.tobytes())
                    frames += 1
                    ok, frame = cap.read()
                proc.stdin.close()
            except BrokenPipeError:
                pass  # ffmpeg died; its exit code and stderr are reported below
            except BaseException:
                proc.kill()
                raise
            finally:
                code = proc.wait()
            if code != 0:
                err.seek(0)
                tail = err.read()[-500:].decode("utf-8", "replace")
                raise MaskError("encode_failed", f"ffmpeg exited with {code}: {tail}", True)
        return MaskStats(frames, with_face)
    finally:
        cap.release()
