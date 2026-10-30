"""Integration tests for `mantis scan`.

Requires the lab to be running on 127.0.0.1:8000.
If not, tests are skipped.
"""

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"


def _lab_running() -> bool:
    try:
        httpx.get("http://127.0.0.1:8000/health", timeout=1.0)
        return True
    except httpx.HTTPError:
        return False


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mantis", "scan"] + args,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture(autouse=True)
def _require_lab():
    if not _lab_running():
        pytest.skip("Lab is not running on 127.0.0.1:8000")
    # Reset the lab to a known state
    httpx.post(
        "http://127.0.0.1:8000/lab/reset",
        headers={"X-API-Key": "lab-admin-key"},
        timeout=2.0,
    )


def test_scan_detects_bola():
    result = _run([
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "employee:lab-employee-key",
        "--no-log",
    ])
    assert result.returncode == 1, f"stderr: {result.stderr}\nstdout: {result.stdout}"
    assert "Findings: 2" in result.stdout  # invoices 3 and 4
    assert "BOLA" in result.stdout


def test_scan_json_output():
    result = _run([
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "employee:lab-employee-key",
        "--json",
        "--no-log",
    ])
    assert result.returncode == 1
    findings = json.loads(result.stdout)
    assert len(findings) == 2
    assert all(f["type"] == "BOLA" for f in findings)


def test_scan_missing_identities():
    result = _run([
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", "admin:lab-admin-key",
    ])
    assert result.returncode == 2
    assert "at least two" in result.stderr


def test_scan_missing_spec():
    result = _run([
        str(EXAMPLES / "nope.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "employee:lab-employee-key",
    ])
    assert result.returncode == 4
    assert "SpecLoadError" in result.stderr