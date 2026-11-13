"""Rigorous verification of MK-007 regression detection.

Key scenario: a baseline contains a finding that no longer exists.
Regression must report it as "corrected" and exit 1.

We do NOT modify the lab. Instead, we inject an artificial finding
into the baseline. This simulates "a vulnerability was fixed and
the finding disappeared". Deterministic and safe.
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


def _scan_and_save_baseline(tmp_path: Path) -> Path:
    """Run a scan and save the baseline."""
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


def _add_fake_finding(baseline: Path, fake_id: str) -> None:
    data = json.loads(baseline.read_text(encoding="utf-8"))
    data["expected_findings"].append({"id": fake_id, "type": "BOLA"})
    baseline.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# --- Key scenario: corrected finding ---

def test_regression_detects_corrected_finding(tmp_path: Path):
    """If a finding in the baseline is no longer detected, regression reports 'corrected'."""
    baseline = _scan_and_save_baseline(tmp_path)
    _add_fake_finding(baseline, "BOLA-fake-999")

    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--no-log",
    ])

    assert result.returncode == 1, f"Expected exit 1 (changes), got {result.returncode}. stderr: {result.stderr}"
    assert "Corrected" in result.stdout
    assert "BOLA-fake-999" in result.stdout
    assert "CHANGED" in result.stdout


def test_regression_corrected_finding_in_json(tmp_path: Path):
    """Same scenario, but verify the JSON output has the corrected list."""
    baseline = _scan_and_save_baseline(tmp_path)
    _add_fake_finding(baseline, "BOLA-fake-999")

    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--format", "json",
        "--no-log",
    ])

    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert "BOLA-fake-999" in data["corrected"]
    assert data["new"] == []
    assert len(data["still_present"]) >= 4


# --- Unchanged scenario ---

def test_regression_unchanged_after_reset(tmp_path: Path):
    """Resetting the lab does not change findings. Regression reports 'expected'."""
    baseline = _scan_and_save_baseline(tmp_path)
    httpx.post(f"{LAB_URL}/lab/reset", headers={"X-API-Key": ADMIN_KEY}, timeout=2.0)

    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--no-log",
    ])

    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}. stderr: {result.stderr}"
    assert "EXPECTED" in result.stdout
    assert "Corrected" not in result.stdout or "Corrected (0)" not in result.stdout


# --- New findings scenario ---

def test_regression_detects_new_findings(tmp_path: Path):
    """If actual findings exceed baseline, they appear as 'new'."""
    baseline = _scan_and_save_baseline(tmp_path)
    # Remove one finding from expected. Now regression should see it as "new"
    data = json.loads(baseline.read_text(encoding="utf-8"))
    removed = data["expected_findings"].pop(0)
    baseline.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    result = _run([
        "run", str(baseline),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--format", "json",
        "--no-log",
    ])

    assert result.returncode == 1
    data_out = json.loads(result.stdout)
    assert len(data_out["new"]) >= 1
    assert removed["id"] in data_out["new"]


# --- Determinism ---

def test_regression_is_deterministic(tmp_path: Path):
    baseline = _scan_and_save_baseline(tmp_path)

    def _run_once() -> dict:
        result = _run([
            "run", str(baseline),
            "--identity", f"admin:{ADMIN_KEY}",
            "--identity", f"employee:{EMPLOYEE_KEY}",
            "--format", "json",
            "--no-log",
        ])
        return json.loads(result.stdout)

    a = _run_once()
    b = _run_once()
    assert sorted(a["still_present"]) == sorted(b["still_present"])
    assert a["corrected"] == b["corrected"]
    assert a["new"] == b["new"]