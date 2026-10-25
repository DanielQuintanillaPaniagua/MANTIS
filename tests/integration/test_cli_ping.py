"""Integration test: `mantis ping` against the real lab.

Starts the lab, pings /health, checks exit code and output.
"""

import json
import subprocess
import sys

import pytest


def test_ping_health_against_running_lab(tmp_path):
    """Requires the lab to be running on 127.0.0.1:8000.

    If not running, this test is skipped (not failed).
    """
    import httpx

    try:
        httpx.get("http://127.0.0.1:8000/health", timeout=1.0)
    except httpx.HTTPError:
        pytest.skip("Lab is not running on 127.0.0.1:8000")

    log_path = tmp_path / "requests.jsonl"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mantis",
            "ping",
            "http://127.0.0.1:8000/health",
            "--log",
            str(log_path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "200" in result.stdout
    assert "duration:" in result.stdout
    assert "size:" in result.stdout

    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    log = json.loads(lines[0])
    assert log["method"] == "GET"
    assert log["status"] == 200