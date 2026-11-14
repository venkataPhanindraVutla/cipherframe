"""The pinned YuNet face detection model (OpenCV Zoo, MIT). The file is fetched, not committed."""

import hashlib
import os
from pathlib import Path

MODEL_FILE = "face_detection_yunet_2026may.onnx"
MODEL_SHA256 = "ebafce4e3c118d6554634be5c27ab333b4c047a9a8c3faf1d7cf93101c22f0f0"
ZOO_COMMIT = "48b10fa505aeb51fbd127fc60a5c660040e823b7"
# The zoo keeps .onnx files in Git LFS; raw.githubusercontent.com serves only the LFS pointer,
# media.githubusercontent.com serves the file itself.
MODEL_URL = (
    "https://media.githubusercontent.com/media/opencv/opencv_zoo/"
    f"{ZOO_COMMIT}/models/face_detection_yunet/{MODEL_FILE}"
)
MODEL_ID = "yunet"
MODEL_VERSION = "2026may"
DEFAULT_MODEL_PATH = Path(os.environ.get("CIPHERFRAME_ML_MODEL_PATH", f"models/{MODEL_FILE}"))


class ModelError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_model(path: Path) -> Path:
    """Refuse a missing or altered model file."""
    if not path.is_file():
        raise ModelError(f"model file not found: {path} (run scripts/fetch_model.py)")
    if sha256_file(path) != MODEL_SHA256:
        raise ModelError(f"model file {path} does not match the pinned SHA-256")
    return path
