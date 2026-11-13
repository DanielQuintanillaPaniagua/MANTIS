"""Rigorous verification of MK-006 combined detection.

Answers one question:
"Does MANTIS detect exactly V1, V2, V3 (and nothing else)?"

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


def _reset_lab() -> None:
    httpx.post(f"{LAB_URL}/lab/reset", headers={"X-API-Key": ADMIN_KEY}, timeout=2.0)


def _run_scan(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mantis", "scan"] + args,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture(autouse=True)
def _require_lab():
    if not _lab_running():
        pytest.skip("Lab is not running on 127.0.0.1:8000")
    _reset_lab()


def _base_args() -> list[str]:
    return [
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", f"admin:{ADMIN_KEY}",
        "--identity", f"employee:{EMPLOYEE_KEY}",
        "--json",
        "--no-log",
        "--max-requests", "300",
        "--reset-endpoint", "/lab/reset",
        "--identity-endpoint", "/me",
    ]


def _scan(args: list[str]) -> list[dict]:
    result = _run_scan(args)
    assert result.returncode in (0, 1), f"unexpected exit {result.returncode}: {result.stderr}"
    return json.loads(result.stdout)


# --- Mode: BOLA only (no --sequences) ---

def test_bola_only_mode_detects_only_v1():
    """Without --sequences, only BOLA is detected (V1 on invoices 3 and 4)."""
    findings = _scan(_base_args())
    assert len(findings) == 2, f"Expected 2 BOLA findings, got {len(findings)}: {[f['id'] for f in findings]}"
    for f in findings:
        assert f["type"] == "BOLA"


def test_bola_only_does_not_report_bfla_or_state_skip():
    findings = _scan(_base_args())
    types = {f["type"] for f in findings}
    assert "BFLA" not in types
    assert "STATE_SKIP" not in types


# --- Mode: full (--sequences) ---

def test_sequences_mode_detects_all_three():
    """With --sequences and privileged_operations, V1, V2, and V3 are all detected."""
    findings = _scan(
        _base_args() + ["--sequences", "--privileged-operations", "approve"]
    )
    types = {f["type"] for f in findings}
    assert "BOLA" in types, f"No BOLA found: {types}"
    assert "BFLA" in types, f"No BFLA found: {types}"
    assert "STATE_SKIP" in types, f"No STATE_SKIP found: {types}"


def test_sequences_mode_has_two_bola():
    """V1 affects invoices 3 and 4, in any mode."""
    findings = _scan(
        _base_args() + ["--sequences", "--privileged-operations", "approve"]
    )
    bola = [f for f in findings if f["type"] == "BOLA"]
    assert len(bola) == 2, f"Expected 2 BOLA, got {len(bola)}: {[f['id'] for f in bola]}"


def test_sequences_mode_has_at_least_one_bfla():
    findings = _scan(
        _base_args() + ["--sequences", "--privileged-operations", "approve"]
    )
    bfla = [f for f in findings if f["type"] == "BFLA"]
    assert len(bfla) >= 1, f"No BFLA found"
    for f in bfla:
        assert "/approve" in f["operation_path"]
        assert f["confidence"] == "medium"


def test_sequences_mode_has_at_least_one_state_skip():
    findings = _scan(
        _base_args() + ["--sequences", "--privileged-operations", "approve"]
    )
    skips = [f for f in findings if f["type"] == "STATE_SKIP"]
    assert len(skips) >= 1, f"No STATE_SKIP found"
    for f in skips:
        assert "/approve" in f["operation_path"]
        assert f["confidence"] == "medium"


# --- No false positives from V2 (submit is legitimate) ---

def test_no_bfla_on_submit():
    """Submit is legitimate for employee. Must NOT be reported as BFLA."""
    findings = _scan(
        _base_args() + ["--sequences", "--privileged-operations", "approve"]
    )
    for f in findings:
        if f["type"] == "BFLA":
            assert "/submit" not in f["operation_path"], (
                f"Submit reported as BFLA: {f['id']}"
            )


# --- Without privileged_operations, BFLA is not detected ---

def test_no_bfla_without_privileged_operations():
    findings = _scan(_base_args() + ["--sequences"])
    bfla = [f for f in findings if f["type"] == "BFLA"]
    assert bfla == [], (
        f"BFLA should not be detected without --privileged-operations: "
        f"{[f['id'] for f in bfla]}"
    )


def test_state_skip_still_works_without_privileged_operations():
    """State skip doesn't need privileged_operations, only sequences."""
    findings = _scan(_base_args() + ["--sequences"])
    skips = [f for f in findings if f["type"] == "STATE_SKIP"]
    assert len(skips) >= 1, "STATE_SKIP should still be detected"


# --- No false positives on Norte invoices ---

def test_bola_does_not_flag_norte_invoices():
    findings = _scan(_base_args())
    for f in findings:
        if f["type"] == "BOLA":
            urls = [ev["url"] for ev in f["evidence"]]
            for url in urls:
                resource_id = url.rstrip("/").rsplit("/", 1)[-1]
                assert resource_id in ("3", "4"), (
                    f"BOLA on unexpected resource: {url}"
                )


# --- Determinism ---

def test_sequences_deterministic():
    args = _base_args() + ["--sequences", "--privileged-operations", "approve"]
    ids_a = sorted(f["id"] for f in _scan(args))
    ids_b = sorted(f["id"] for f in _scan(args))
    assert ids_a == ids_b