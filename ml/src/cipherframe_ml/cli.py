"""cipherframe-ml command line."""

import argparse
import logging
import sys

from .config import Config, ConfigError
from .mask import YuNetDetector
from .model import ModelError, verify_model
from .worker import serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cipherframe-ml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("mask-worker", help="claim and run media.mask_faces tasks")
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = Config.from_env()
        detect = YuNetDetector(verify_model(cfg.model_path))
    except (ConfigError, ModelError) as e:
        print(f"cipherframe-ml: {e}", file=sys.stderr)
        return 2
    try:
        serve(cfg, detect)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
