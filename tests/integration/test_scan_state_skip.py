"""Integration test for state skip detection against the real lab."""

from pathlib import Path

import httpx
import pytest

from mantis.analysis.authorization import Identity
from mantis.analysis.sequences import detect_state_skip
from mantis.core.config import MantisConfig
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec
from mantis.transport.client import MantisClient


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"
LAB_URL = "http://127.0.0.1:8000"
ADMIN_KEY = "lab-admin-key"


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


def _config() -> MantisConfig:
    return MantisConfig(max_requests=200, requests_per_minute=200)


def _load_spec():
    return parse_spec(load_spec(EXAMPLES / "mantis-lab.json"))


def test_detects_state_skip_on_approve_draft():
    """Admin approves a draft invoice (V3). MANTIS must detect it."""
    spec = _load_spec()
    admin = Identity("admin", ADMIN_KEY, LAB_URL)
    config = _config()

    with MantisClient(config) as client:
        findings = detect_state_skip(spec, client, config, admin)

    assert len(findings) >= 1, f"No state skip found. All: {[f.id for f in findings]}"
    finding = findings[0]
    assert finding.type.value == "STATE_SKIP"
    assert "approve" in finding.operation_path
    assert finding.confidence.value == "medium"
    assert "approved" in finding.details


def test_state_skip_is_deterministic():
    spec = _load_spec()
    admin = Identity("admin", ADMIN_KEY, LAB_URL)
    config = _config()

    def _run():
        with MantisClient(config) as client:
            return detect_state_skip(spec, client, config, admin)

    ids_a = sorted(f.id for f in _run())
    ids_b = sorted(f.id for f in _run())
    assert ids_a == ids_b