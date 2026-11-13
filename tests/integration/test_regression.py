"""Integration tests for `mantis regression run`.

Requires the lab on 127.0.0.1:8000. Skips otherwise.
"""

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"
LAB_URL = "http://127.0.0.1:8000"
ADMIN_KEY = "lab-admin-key"
EMPLOYEE_KEY = "lab-employee-key"


def _lab_running() -> bool:
    try:
        httpx.get(f"{LAB_URL}/health", timeout=1.0)
        return True
    except httpx.HTTPError:
        return False


@pytest.fixture(autouse=True)
def _require_lab():
    if not _lab_running():
        pytest.skip("Lab is not running on 127.0.0.1:8000")
    httpx.post(f"{LAB_URL}/lab/reset", headers={"X-API-Key": ADMIN_KEY}, timeout=2.0)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mantis", "regression"] + args,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _build_baseline(tmp_path: Path) -> Path:
    """Build a baseline by running a scan."""
    baseline = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "mantis", "scan",
            str(EXAMPLES / "mantis-lab.json"),
            "--identity", f"admin:{ADMIN_KEY}",
            "--identity", f"employee:{EMPLOYEE_KEY}",
            "--sequences",
            "--privileged-operations", "approve",
            "--allowed-transition", "status:draft->submitted",
            "--allowed-transition", "status:submitted->approved",
            "--max-requests", "200",
            "--reset-endpoint", "/lab/reset",
            "--identity-endpoint", "/me",
            "--save-baseline", str(baseline),
            "--no-log",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert baseline.exists(), f"Baseline not created. stderr: {result.stderr}"
    return baseline


def test_regression_unchanged(tmp_path: Path):
    """Running regression right after scan produces exit 0 (nothing changed)."""
    baseline = _build_baseline(tmp_path)
    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--no-log",
    ])
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}. stderr: {result.stderr}"
    assert "EXPECTED" in result.stdout


def test_regression_json(tmp_path: Path):
    baseline = _build_baseline(tmp_path)
    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--format", "json",
        "--no-log",
    ])
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["corrected"] == []
    assert data["new"] == []
    assert len(data["still_present"]) >= 4


def test_regression_empty_baseline_detects_new(tmp_path: Path):
    """If baseline is empty but actual findings exist, exit 1 and 'new' populated."""
    baseline = tmp_path / "empty.json"
    baseline.write_text(
        json.dumps({
            "spec": str(EXAMPLES / "mantis-lab.json"),
            "spec_title": "MANTIS Lab",
            "options": {
                "sequences": False,
                "privileged_operations": [],
                "allowed_transitions": [],
                "max_requests": 200,
                "base_url": LAB_URL,
            },
            "identities": [{"name": "admin"}, {"name": "employee"}],
            "expected_findings": [],
        }),
        encoding="utf-8",
    )
    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--no-log",
    ])
    assert result.returncode == 1
    assert "New" in result.stdout


def test_regression_missing_baseline():
    result = _run([
        "run", "/nonexistent/baseline.json",
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
    ])
    assert result.returncode == 4
    assert "not found" in result.stderr


def test_regression_missing_subcommand():
    result = _run([])
    assert result.returncode == 2
    assert "missing subcommand" in result.stderr