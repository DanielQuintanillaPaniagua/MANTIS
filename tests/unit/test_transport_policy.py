"""Unit tests for TargetPolicy."""

import pytest

from mantis.core.config import MantisConfig
from mantis.transport.policy import TargetNotAllowed, TargetPolicy


def _policy() -> TargetPolicy:
    return TargetPolicy.from_config(MantisConfig())


def test_allows_lab_http():
    _policy().check("http://127.0.0.1:8000/health")


def test_allows_lab_localhost():
    _policy().check("http://localhost:8000/health")


def test_allows_lab_https():
    _policy().check("https://127.0.0.1:8000/health")


def test_rejects_unknown_host():
    with pytest.raises(TargetNotAllowed):
        _policy().check("http://example.com/health")


def test_rejects_unknown_port():
    with pytest.raises(TargetNotAllowed):
        _policy().check("http://127.0.0.1:22/")


def test_rejects_unknown_scheme():
    with pytest.raises(TargetNotAllowed):
        _policy().check("ftp://127.0.0.1:8000/")


def test_rejects_missing_scheme():
    with pytest.raises(TargetNotAllowed):
        _policy().check("127.0.0.1:8000/health")


def test_host_comparison_is_case_insensitive():
    _policy().check("http://LOCALHOST:8000/health")


def test_missing_port_infers_default_http():
    """http without port implies 80, which is not in allowed_ports."""
    with pytest.raises(TargetNotAllowed):
        _policy().check("http://127.0.0.1/health")


def test_custom_policy_allows_different_host():
    config = MantisConfig(allowed_hosts=("example.com",), allowed_ports=(443,))
    policy = TargetPolicy.from_config(config)
    policy.check("https://example.com/health")


def test_custom_policy_rejects_lab():
    config = MantisConfig(allowed_hosts=("example.com",), allowed_ports=(443,))
    policy = TargetPolicy.from_config(config)
    with pytest.raises(TargetNotAllowed):
        policy.check("http://127.0.0.1:8000/health")