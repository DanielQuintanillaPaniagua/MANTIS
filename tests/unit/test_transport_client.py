"""Unit tests for MantisClient.

Uses httpx.MockTransport to simulate responses without touching the
network. No real HTTP. Fast, deterministic.
"""

import json
from pathlib import Path

import httpx
import pytest

from mantis.core.config import MantisConfig
from mantis.transport.client import MantisClient, RateLimitExceeded
from mantis.transport.log import RequestLogWriter


def _mock_transport(handler):
    """Wrap a handler function into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def test_get_returns_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    config = MantisConfig()
    with MantisClient(config, transport=_mock_transport(handler)) as client:
        response = client.get("http://test/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_get_with_headers_sends_them():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200)

    config = MantisConfig()
    with MantisClient(config, transport=_mock_transport(handler)) as client:
        client.get("http://test/x", headers={"X-API-Key": "secret"})

    assert captured["headers"].get("x-api-key") == "secret"


def test_evidence_logged_on_success(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"ok")

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            client.get("http://test/x")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    log = json.loads(lines[0])
    assert log["method"] == "GET"
    assert log["url"] == "http://test/x"
    assert log["status"] == 200
    assert log["error"] is None
    assert log["response_size"] == 2


def test_evidence_logged_on_network_error(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            with pytest.raises(httpx.ConnectError):
                client.get("http://test/x")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    log = json.loads(lines[0])
    assert log["status"] == 0
    assert "ConnectError" in log["error"]


def test_max_requests_enforced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    config = MantisConfig(max_requests=2, requests_per_minute=100)
    with MantisClient(config, transport=_mock_transport(handler)) as client:
        client.get("http://test/1")
        client.get("http://test/2")
        with pytest.raises(RateLimitExceeded):
            client.get("http://test/3")


def test_requests_per_minute_enforced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    config = MantisConfig(max_requests=100, requests_per_minute=2)
    with MantisClient(config, transport=_mock_transport(handler)) as client:
        client.get("http://test/1")
        client.get("http://test/2")
        with pytest.raises(RateLimitExceeded):
            client.get("http://test/3")


def test_timeout_passed_to_httpx():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["timeout"] = request.extensions.get("timeout")
        return httpx.Response(200)

    config = MantisConfig(timeout_seconds=2.5)
    with MantisClient(config, transport=_mock_transport(handler)) as client:
        client.get("http://test/x")

    assert captured["timeout"] is not None
    assert captured["timeout"].get("connect") == 2.5
def test_evidence_redacts_sensitive_request_headers(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            client.get(
                "http://test/x",
                headers={
                    "X-API-Key": "secret-key",
                    "Authorization": "Bearer secret-token",
                    "Accept": "application/json",
                },
            )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log = json.loads(lines[0])
    assert log["request_headers"]["X-API-Key"] == "***REDACTED***"
    assert log["request_headers"]["Authorization"] == "***REDACTED***"
    assert log["request_headers"]["Accept"] == "application/json"


def test_evidence_redacts_sensitive_response_headers(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Set-Cookie": "session=secret", "Content-Type": "application/json"},
        )

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            client.get("http://test/x")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log = json.loads(lines[0])
    assert log["response_headers"]["set-cookie"] == "***REDACTED***"
    assert log["response_headers"]["content-type"] == "application/json"


def test_evidence_redacts_query_params(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            client.get("http://test/x?api_key=secret&page=2&token=abc")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log = json.loads(lines[0])
    assert "secret" not in log["url"]
    assert "abc" not in log["url"]
    assert "page=2" in log["url"]


def test_redaction_is_case_insensitive(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    log_path = tmp_path / "requests.jsonl"
    config = MantisConfig()
    with RequestLogWriter(log_path) as writer:
        with MantisClient(config, log_writer=writer, transport=_mock_transport(handler)) as client:
            client.get("http://test/x", headers={"X-API-KEY": "secret"})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log = json.loads(lines[0])
    assert log["request_headers"]["X-API-KEY"] == "***REDACTED***"
    