
import pytest

from mantis.core.config import MantisConfig


def test_default_configuration():
    config = MantisConfig()

    assert config.timeout_seconds == 5.0
    assert config.max_requests == 20
    assert config.requests_per_minute == 20


def test_rejects_zero_timeout():
    with pytest.raises(ValueError):
        MantisConfig(timeout_seconds=0)


def test_rejects_invalid_request_limit():
    with pytest.raises(ValueError):
        MantisConfig(max_requests=0)
def test_rejects_nan_timeout():
    import math

    with pytest.raises(ValueError):
        MantisConfig(timeout_seconds=float("nan"))


def test_rejects_positive_infinity_timeout():
    with pytest.raises(ValueError):
        MantisConfig(timeout_seconds=float("inf"))


def test_rejects_negative_infinity_timeout():
    with pytest.raises(ValueError):
        MantisConfig(timeout_seconds=float("-inf"))


def test_rejects_negative_timeout():
    with pytest.raises(ValueError):
        MantisConfig(timeout_seconds=-1.0)


def test_accepts_small_positive_timeout():
    config = MantisConfig(timeout_seconds=0.1)
    assert config.timeout_seconds == 0.1