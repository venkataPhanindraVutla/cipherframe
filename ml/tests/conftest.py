import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

SPEC = Path(__file__).resolve().parents[2] / "spec" / "jobs"


def validator(rel: str) -> Draft202012Validator:
    schema = json.loads((SPEC / rel).read_text())
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture(scope="session")
def ffmpeg() -> str:
    path = shutil.which("ffmpeg")
    if not path:
        pytest.skip("ffmpeg not installed")
    return path
