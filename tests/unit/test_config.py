
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
