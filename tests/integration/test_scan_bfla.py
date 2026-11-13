"""Integration test for BFLA detection against the real lab.

Requires the lab to be running on 127.0.0.1:8000.
Skips otherwise.
"""

import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from mantis.analysis.authorization import Identity
from mantis.analysis.sequences import detect_bfla
from mantis.core.config import MantisConfig
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec
from mantis.transport.client import MantisClient


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


def _load_spec_and_parse():
    return parse_spec(load_spec(EXAMPLES / "mantis-lab.json"))


def _bfla_config() -> MantisConfig:
    """Config with high limits and privileged operations for BFLA tests."""
    return MantisConfig(
        max_requests=200,
        requests_per_minute=200,
        privileged_operations=("approve",),
        reset_endpoint="/lab/reset",
        identity_endpoints=("/me",),
    )


def test_bfla_detected_on_approve():
    """Employee can approve invoice 2 (V2). MANTIS must detect it."""
    spec = _load_spec_and_parse()
    admin = Identity("admin", ADMIN_KEY, LAB_URL)
    employee = Identity("employee", EMPLOYEE_KEY, LAB_URL)
    config = _bfla_config()

    with MantisClient(config) as client:
        findings = detect_bfla(spec, client, config, admin, employee)

    bfla_findings = [f for f in findings if f.type.value == "BFLA"]
    assert len(bfla_findings) >= 1, f"No BFLA found. All: {[f.id for f in findings]}"

    approve_finding = next(
        f for f in bfla_findings if "/approve" in f.operation_path
    )
    assert approve_finding.identity == "employee"
    assert approve_finding.confidence.value == "medium"
    assert "approved" in approve_finding.details


def test_bfla_not_detected_on_submit():
    """Submit is legitimate for employee. Must not be reported as BFLA."""
    spec = _load_spec_and_parse()
    admin = Identity("admin", ADMIN_KEY, LAB_URL)
    employee = Identity("employee", EMPLOYEE_KEY, LAB_URL)
    config = _bfla_config()

    with MantisClient(config) as client:
        findings = detect_bfla(spec, client, config, admin, employee)

    submit_findings = [f for f in findings if "/submit" in f.operation_path]
    assert submit_findings == [], (
        f"Submit is legitimate for employee, should not be BFLA: {[f.id for f in submit_findings]}"
    )


def test_bfla_is_deterministic():
    """Two consecutive scans produce the same BFLA findings."""
    spec = _load_spec_and_parse()
    admin = Identity("admin", ADMIN_KEY, LAB_URL)
    employee = Identity("employee", EMPLOYEE_KEY, LAB_URL)
    config = _bfla_config()

    def _run():
        with MantisClient(config) as client:
            return detect_bfla(spec, client, config, admin, employee)

    ids_a = sorted(f.id for f in _run())
    ids_b = sorted(f.id for f in _run())
    assert ids_a == ids_b