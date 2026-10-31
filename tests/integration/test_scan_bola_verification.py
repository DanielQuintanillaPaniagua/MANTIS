"""Rigorous verification of MK-005 BOLA detection.

This test file answers one question:
"Does MANTIS detect exactly V1 (invoices 3 and 4) and nothing else?"

If MANTIS ever finds something not listed here, it is a false positive.
If MANTIS misses any of the two, it is a false negative.

Requires the lab to be running on 127.0.0.1:8000.
"""

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"
LAB_URL = "http://127.0.0.1:8000"


def _lab_running() -> bool:
    try:
        httpx.get(f"{LAB_URL}/health", timeout=1.0)
        return True
    except httpx.HTTPError:
        return False


def _reset_lab() -> None:
    httpx.post(
        f"{LAB_URL}/lab/reset",
        headers={"X-API-Key": "lab-admin-key"},
        timeout=2.0,
    )


def _run_scan(args: list[str]) -> subprocess.CompletedProcess:
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
    _reset_lab()


def _scan_default() -> list[dict]:
    result = _run_scan([
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "employee:lab-employee-key",
        "--json",
        "--no-log",
    ])
    assert result.returncode == 1, f"expected exit 1, got {result.returncode}. stderr: {result.stderr}"
    return json.loads(result.stdout)


# --- Determinism ---

def test_scan_is_deterministic():
    """Two consecutive scans produce identical findings."""
    findings_a = _scan_default()
    findings_b = _scan_default()

    ids_a = sorted(f["id"] for f in findings_a)
    ids_b = sorted(f["id"] for f in findings_b)
    assert ids_a == ids_b


def test_scan_after_reset_produces_same_results():
    """Resetting the lab does not change which resources are flagged."""
    findings_a = _scan_default()
    _reset_lab()
    findings_b = _scan_default()

    ids_a = sorted(f["id"] for f in findings_a)
    ids_b = sorted(f["id"] for f in findings_b)
    assert ids_a == ids_b


# --- Correct number of findings (no false positives) ---

def test_scan_finds_exactly_two_v1_findings():
    """V1 affects exactly invoices 3 and 4 (Sur, employee is Norte)."""
    findings = _scan_default()
    assert len(findings) == 2, (
        f"Expected exactly 2 findings (V1 on invoices 3 and 4), "
        f"got {len(findings)}: {[f['id'] for f in findings]}"
    )


def test_all_findings_are_bola_type():
    findings = _scan_default()
    for f in findings:
        assert f["type"] == "BOLA", f"Unexpected type: {f['type']}"


def test_findings_target_invoice_endpoint():
    """The findings must be on GET /invoices/{invoice_id}, not on /approve."""
    findings = _scan_default()
    for f in findings:
        assert f["operation_path"] == "/invoices/{invoice_id}", (
            f"Unexpected operation: {f['operation_path']}"
        )
        assert f["operation_method"] == "GET"


def test_findings_are_on_sur_invoices():
    findings = _scan_default()
    flagged_urls = set()
    for f in findings:
        # Each finding has 2 evidence entries; the URL ends with the resource id
        for ev in f["evidence"]:
            url = ev["url"]
            resource_id = url.rstrip("/").rsplit("/", 1)[-1]
            flagged_urls.add(resource_id)
    assert flagged_urls == {"3", "4"}, (
        f"Expected resources 3 and 4, got {flagged_urls}"
    )


def test_no_findings_on_norte_invoices():
    """Invoices 1 and 2 (Norte) are NOT vulnerable to V1. They must not appear."""
    findings = _scan_default()
    for f in findings:
        assert "_1" not in f["id"] or "_11" in f["id"], (
            f"Unexpected finding on invoice 1: {f['id']}"
        )
        assert "_2" not in f["id"] or "_12" in f["id"], (
            f"Unexpected finding on invoice 2: {f['id']}"
        )


# --- No false positives from other vulnerabilities ---

def test_scan_does_not_report_v2():
    """V2 (BFLA on /approve) is not detected by MK-005. Only V1."""
    findings = _scan_default()
    for f in findings:
        assert "/approve" not in f["operation_path"], (
            f"MK-005 should not detect V2 yet: {f['id']}"
        )


def test_scan_does_not_report_v3():
    """V3 (state skip) is not detected by MK-005. Only V1."""
    findings = _scan_default()
    for f in findings:
        assert "submit" not in f["operation_path"], (
            f"MK-005 should not detect V3: {f['id']}"
        )


# --- Finding content ---

def test_findings_have_evidence():
    findings = _scan_default()
    for f in findings:
        assert len(f["evidence"]) == 2, "Each finding should have 2 evidence entries"
        descriptions = [e["description"] for e in f["evidence"]]
        assert any("admin" in d for d in descriptions)
        assert any("employee" in d for d in descriptions)


def test_findings_have_reproduction_steps():
    findings = _scan_default()
    for f in findings:
        assert len(f["reproduction"]) >= 3
        # First step mentions identity B
        assert "employee" in f["reproduction"][0]


def test_findings_mention_branch_mismatch():
    """Details must explain the S001 vs S002 mismatch."""
    findings = _scan_default()
    for f in findings:
        assert "S001" in f["details"], f"S001 not in details: {f['details']}"
        assert "S002" in f["details"], f"S002 not in details: {f['details']}"


# --- Edge cases ---

def test_scan_with_identical_identities_finds_nothing():
    """If both identities are the same, no BOLA can be detected."""
    result = _run_scan([
        str(EXAMPLES / "mantis-lab.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "admin2:lab-admin-key",
        "--json",
        "--no-log",
    ])
    assert result.returncode == 0, f"stderr: {result.stderr}"
    findings = json.loads(result.stdout)
    assert findings == []


def test_scan_against_spec_without_object_operations():
    """minimal-valid.json has only GET /ping. No BOLA possible."""
    result = _run_scan([
        str(EXAMPLES / "minimal-valid.json"),
        "--identity", "admin:lab-admin-key",
        "--identity", "employee:lab-employee-key",
        "--json",
        "--no-log",
    ])
    assert result.returncode == 0, f"stderr: {result.stderr}"
    findings = json.loads(result.stdout)
    assert findings == []