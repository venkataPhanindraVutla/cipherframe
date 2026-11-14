"""Download the pinned YuNet model and verify its SHA-256 (usage: fetch_model.py [DEST_DIR])."""

import sys
import urllib.request
from pathlib import Path

from cipherframe_ml.model import MODEL_FILE, MODEL_URL, ModelError, verify_model


def main() -> None:
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "models") / MODEL_FILE
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    with urllib.request.urlopen(MODEL_URL, timeout=60) as r, tmp.open("wb") as f:  # noqa: S310
        f.write(r.read())
    try:
        verify_model(tmp)
    except ModelError:
        tmp.unlink()
        raise
    tmp.replace(dest)
    print(f"ok {dest}")


if __name__ == "__main__":
    main()
