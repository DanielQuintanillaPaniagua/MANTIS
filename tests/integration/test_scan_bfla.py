"""Integration test for BFLA detection using in-memory lab."""

from pathlib import Path

from mantis.analysis.authorization import Identity
from mantis.analysis.sequences import detect_bfla
from mantis.core.config import MantisConfig
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"
LAB_URL = "http://127.0.0.1:8000"


def _load_spec():
    return parse_spec(load_spec(EXAMPLES / "mantis-lab.json"))


def _bfla_config() -> MantisConfig:
    return MantisConfig(
        max_requests=200,
        requests_per_minute=200,
        privileged_operations=("approve",),
        reset_endpoint="/lab/reset",
        identity_endpoints=("/me",),
    )


def test_bfla_detected_on_approve(mantis_client):
    """Employee can approve invoice 2 (V2). MANTIS must detect it."""
    spec = _load_spec()
    admin = Identity("admin", "lab-admin-key", LAB_URL)
    employee = Identity("employee", "lab-employee-key", LAB_URL)
    config = _bfla_config()

    with mantis_client(config) as client:
        findings = detect_bfla(spec, client, config, admin, employee)

    bfla_findings = [f for f in findings if f.type.value == "BFLA"]
    assert len(bfla_findings) >= 1, f"No BFLA found. All: {[f.id for f in findings]}"

    approve_finding = next(
        f for f in bfla_findings if "/approve" in f.operation_path
    )
    assert approve_finding.identity == "employee"
    assert approve_finding.confidence.value == "medium"
    assert "approved" in approve_finding.details


def test_bfla_not_detected_on_submit(mantis_client):
    """Submit is legitimate for employee. Must not be reported as BFLA."""
    spec = _load_spec()
    admin = Identity("admin", "lab-admin-key", LAB_URL)
    employee = Identity("employee", "lab-employee-key", LAB_URL)
    config = _bfla_config()

    with mantis_client(config) as client:
        findings = detect_bfla(spec, client, config, admin, employee)

    submit_findings = [f for f in findings if "/submit" in f.operation_path]
    assert submit_findings == [], (
        f"Submit is legitimate for employee, should not be BFLA: {[f.id for f in submit_findings]}"
    )


def test_bfla_is_deterministic(mantis_client):
    """Two consecutive scans produce the same BFLA findings."""
    spec = _load_spec()
    admin = Identity("admin", "lab-admin-key", LAB_URL)
    employee = Identity("employee", "lab-employee-key", LAB_URL)
    config = _bfla_config()

    def _run():
        with mantis_client(config) as client:
            return detect_bfla(spec, client, config, admin, employee)

    ids_a = sorted(f.id for f in _run())
    ids_b = sorted(f.id for f in _run())
    assert ids_a == ids_b