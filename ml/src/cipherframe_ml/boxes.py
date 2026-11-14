"""Pure box arithmetic for the masker. A box is (x, y, w, h) in pixels."""

from collections.abc import Sequence

Box = tuple[int, int, int, int]

PAD = 0.25
HOLD_SECONDS = 1.0


def pad_box(box: Sequence[float], frame_w: int, frame_h: int, pad: float = PAD) -> Box:
    """Grow a box by `pad` of its size on every side and clamp it to the frame."""
    x, y, w, h = box
    x0 = max(0, int(x - w * pad))
    y0 = max(0, int(y - h * pad))
    x1 = min(frame_w, int(x + w + w * pad + 0.999))
    y1 = min(frame_h, int(y + h + h * pad + 0.999))
    return (x0, y0, max(0, x1 - x0), max(0, y1 - y0))


def scale_box(box: Sequence[float], factor: float) -> tuple[float, float, float, float]:
    x, y, w, h = box
    return (x * factor, y * factor, w * factor, h * factor)


class Holder:
    """Keeps the last detected boxes for `hold_frames` frames after detection drops."""

    def __init__(self, fps: float, seconds: float = HOLD_SECONDS):
        self.hold_frames = max(1, round(fps * seconds))
        self._boxes: list[Box] = []
        self._age = 0

    def update(self, detected: list[Box]) -> list[Box]:
        if detected:
            self._boxes, self._age = list(detected), 0
        elif self._boxes:
            self._age += 1
            if self._age > self.hold_frames:
                self._boxes = []
        return list(self._boxes)
