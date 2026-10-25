"""Unit tests for the evidence logger."""

import json
from pathlib import Path

from mantis.transport.log import RequestLog, RequestLogWriter, utc_now_iso
import pytest


def test_request_log_serializes_to_valid_json():
    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://127.0.0.1:8000/health",
        status=200,
        duration_ms=12.5,
    )

    line = log.to_json_line()
    parsed = json.loads(line)

    assert parsed["method"] == "GET"
    assert parsed["status"] == 200
    assert parsed["duration_ms"] == 12.5
    assert parsed["error"] is None


def test_request_log_has_no_newlines():
    """A JSON line must be exactly one line."""
    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://example.com",
        status=200,
        duration_ms=1.0,
    )

    line = log.to_json_line()
    assert "\n" not in line


def test_request_log_preserves_unicode():
    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://example.com/año",
        status=200,
        duration_ms=1.0,
        request_headers={"X-Nota": "facturación"},
    )

    line = log.to_json_line()
    parsed = json.loads(line)

    assert parsed["url"] == "http://example.com/año"
    assert parsed["request_headers"]["X-Nota"] == "facturación"


def test_request_log_preserves_quotes_and_special_chars():
    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url='http://example.com/?q="hola"',
        status=200,
        duration_ms=1.0,
        error='timeout "agotado"',
    )

    line = log.to_json_line()
    parsed = json.loads(line)

    assert parsed["url"] == 'http://example.com/?q="hola"'
    assert parsed["error"] == 'timeout "agotado"'


def test_writer_creates_file_and_appends(tmp_path: Path):
    log_path = tmp_path / "requests.jsonl"
    log1 = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://example.com/1",
        status=200,
        duration_ms=1.0,
    )
    log2 = RequestLog(
        timestamp="2026-10-19T12:00:01Z",
        method="POST",
        url="http://example.com/2",
        status=201,
        duration_ms=2.0,
    )

    with RequestLogWriter(log_path) as writer:
        writer.write(log1)
        writer.write(log2)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    parsed1 = json.loads(lines[0])
    parsed2 = json.loads(lines[1])

    assert parsed1["url"] == "http://example.com/1"
    assert parsed2["url"] == "http://example.com/2"


def test_writer_creates_parent_directories(tmp_path: Path):
    log_path = tmp_path / "nested" / "deep" / "requests.jsonl"
    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://example.com",
        status=200,
        duration_ms=1.0,
    )

    with RequestLogWriter(log_path) as writer:
        writer.write(log)

    assert log_path.exists()
    assert log_path.read_text(encoding="utf-8").count("\n") == 1


def test_utc_now_iso_format():
    ts = utc_now_iso()
    # Format: YYYY-MM-DDTHH:MM:SSZ
    assert ts.endswith("Z")
    assert len(ts) == 20
    assert ts[4] == "-"
    assert ts[7] == "-"
    assert ts[10] == "T"
    assert ts[13] == ":"
    assert ts[16] == ":"
def test_writer_raises_evidence_write_error_on_closed_file(tmp_path: Path):
    from mantis.transport.log import EvidenceWriteError

    log_path = tmp_path / "requests.jsonl"
    writer = RequestLogWriter(log_path)
    writer.close()

    log = RequestLog(
        timestamp="2026-10-19T12:00:00Z",
        method="GET",
        url="http://127.0.0.1:8000/health",
        status=200,
        duration_ms=1.0,
    )

    with pytest.raises(EvidenceWriteError):
        writer.write(log)