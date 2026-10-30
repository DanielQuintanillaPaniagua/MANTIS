"""Unit tests for BOLA detection.

Uses httpx.MockTransport. Does not touch the real lab.
"""

import json

import httpx
import pytest

from mantis.analysis.authorization import Identity, detect_bola
from mantis.core.config import MantisConfig
from mantis.spec.models import (
    ApiSpec,
    HttpMethod,
    Operation,
    Parameter,
    ParameterLocation,
)
from mantis.transport.client import MantisClient


ADMIN = Identity(
    name="admin",
    api_key="lab-admin-key",
    base_url="http://127.0.0.1:8000",
)
EMPLOYEE = Identity(
    name="employee",
    api_key="lab-employee-key",
    base_url="http://127.0.0.1:8000",
)


def _spec_with_invoice_op() -> ApiSpec:
    op = Operation(
        method=HttpMethod.GET,
        path="/invoices/{invoice_id}",
        parameters=(
            Parameter(
                name="invoice_id",
                location=ParameterLocation.PATH,
                required=True,
            ),
        ),
    )
    return ApiSpec(
        openapi_version="3.1.0",
        title="Test",
        version="1.0.0",
        operations=(op,),
    )


def _make_client(handler) -> MantisClient:
    config = MantisConfig()
    return MantisClient(config, transport=httpx.MockTransport(handler))


def test_detects_bola_when_employee_reads_other_branch():
    """Admin (branch S001/S002) and employee (branch S001). Employee reads invoice 3 (S002)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/me":
            if key == "lab-admin-key":
                return httpx.Response(200, json={"id": "U001", "branch_id": None})
            if key == "lab-employee-key":
                return httpx.Response(200, json={"id": "U002", "branch_id": "S001"})
            return httpx.Response(401)

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}])

        if path == "/invoices/1":
            return httpx.Response(200, json={"id": 1, "branch_id": "S001"})
        if path == "/invoices/2":
            return httpx.Response(200, json={"id": 2, "branch_id": "S001"})
        if path == "/invoices/3":
            # Vulnerable: employee sees invoice from S002
            return httpx.Response(200, json={"id": 3, "branch_id": "S002"})
        if path == "/invoices/4":
            return httpx.Response(200, json={"id": 4, "branch_id": "S002"})

        return httpx.Response(404)

    config = MantisConfig()
    with _make_client(handler) as client:
        findings = detect_bola(
            _spec_with_invoice_op(), client, config, ADMIN, EMPLOYEE
        )

    assert len(findings) == 2  # invoices 3 and 4
    finding = findings[0]
    assert finding.type.value == "BOLA"
    assert "employee" in finding.identity
    assert finding.operation_path == "/invoices/{invoice_id}"
    assert len(finding.evidence) == 2
    assert "S002" in finding.details


def test_no_finding_when_all_access_correct():
    """Correct behavior: employee only sees own branch."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/me":
            if key == "lab-admin-key":
                return httpx.Response(200, json={"branch_id": None})
            return httpx.Response(200, json={"branch_id": "S001"})

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

        if path in ("/invoices/1", "/invoices/2"):
            return httpx.Response(200, json={"id": int(path[-1]), "branch_id": "S001"})

        if path in ("/invoices/3", "/invoices/4"):
            # Employee gets 403 (correct)
            if key == "lab-employee-key":
                return httpx.Response(403)
            return httpx.Response(200, json={"id": int(path[-1]), "branch_id": "S002"})

        return httpx.Response(404)

    config = MantisConfig()
    with _make_client(handler) as client:
        findings = detect_bola(
            _spec_with_invoice_op(), client, config, ADMIN, EMPLOYEE
        )

    assert findings == ()


def test_no_finding_if_no_me_endpoint():
    """Without /me, we cannot know B's scope. No findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    config = MantisConfig()
    with _make_client(handler) as client:
        findings = detect_bola(
            _spec_with_invoice_op(), client, config, ADMIN, EMPLOYEE
        )

    assert findings == ()


def test_no_finding_if_admin_cannot_read_either():
    """If A cannot read, it is not a BOLA candidate."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/me":
            if key == "lab-employee-key":
                return httpx.Response(200, json={"branch_id": "S001"})
            return httpx.Response(200, json={"branch_id": None})

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}])

        return httpx.Response(403)

    config = MantisConfig()
    with _make_client(handler) as client:
        findings = detect_bola(
            _spec_with_invoice_op(), client, config, ADMIN, EMPLOYEE
        )

    assert findings == ()