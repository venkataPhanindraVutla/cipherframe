import pytest

from cipherframe_ml.config import Config, ConfigError

BASE = {"CIPHERFRAME_ML_DATABASE_URL": "postgres://test-fixture-user@localhost/db"}


def test_detect_every_defaults_to_every_frame():
    assert Config.from_env(BASE).detect_every == 1
    assert Config.from_env({**BASE, "CIPHERFRAME_ML_DETECT_EVERY": ""}).detect_every == 1


@pytest.mark.parametrize("value", ["1", "2", "5"])
def test_detect_every_accepts_whole_numbers(value):
    assert Config.from_env({**BASE, "CIPHERFRAME_ML_DETECT_EVERY": value}).detect_every == int(
        value
    )


@pytest.mark.parametrize("value", ["0", "-1", "2.5", "two", " 2", "٣"])
def test_detect_every_rejects_everything_else(value):
    with pytest.raises(ConfigError, match="CIPHERFRAME_ML_DETECT_EVERY"):
        Config.from_env({**BASE, "CIPHERFRAME_ML_DETECT_EVERY": value})
