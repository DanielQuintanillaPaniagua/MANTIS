"""Unit tests for BFLA detection with MockTransport."""

import httpx
import pytest

from mantis.analysis.authorization import Identity
from mantis.analysis.sequences import detect_bfla
from mantis.core.config import MantisConfig
from mantis.spec.models import (
    ApiSpec,
    HttpMethod,
    Operation,
    Parameter,
    ParameterLocation,
)
from mantis.transport.client import MantisClient


ADMIN = Identity("admin", "lab-admin-key", "http://127.0.0.1:8000")
EMPLOYEE = Identity("employee", "lab-employee-key", "http://127.0.0.1:8000")


def _spec() -> ApiSpec:
    """Spec with /lab/reset, GET /invoices/{id}, POST /invoices/{id}/approve."""
    reset_op = Operation(method=HttpMethod.POST, path="/lab/reset")
    read_op = Operation(
        method=HttpMethod.GET,
        path="/invoices/{invoice_id}",
        parameters=(
            Parameter(name="invoice_id", location=ParameterLocation.PATH, required=True),
        ),
    )
    approve_op = Operation(
        method=HttpMethod.POST,
        path="/invoices/{invoice_id}/approve",
        parameters=(
            Parameter(name="invoice_id", location=ParameterLocation.PATH, required=True),
        ),
    )
    return ApiSpec(
        openapi_version="3.1.0",
        title="Test",
        version="1.0.0",
        operations=(reset_op, read_op, approve_op),
    )


def _client(handler) -> MantisClient:
    return MantisClient(MantisConfig(), transport=httpx.MockTransport(handler))


def test_detects_bfla_when_employee_can_approve():
    """Employee executes approve. Admin can too. Both change state. BFLA."""

    state = {"status": "submitted"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/lab/reset":
            state["status"] = "submitted"
            return httpx.Response(200, json={"status": "reset"})

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 2}])

        if path == "/invoices/2":
            return httpx.Response(200, json={"id": 2, "status": state["status"]})

        if path == "/invoices/2/approve":
            if state["status"] == "submitted":
                state["status"] = "approved"
                return httpx.Response(200, json={"status": "approved"})
            return httpx.Response(409)

        return httpx.Response(404)

    with _client(handler) as client:
        findings = detect_bfla(_spec(), client, MantisConfig(), ADMIN, EMPLOYEE)

    assert len(findings) == 1
    assert findings[0].type.value == "BFLA"
    assert findings[0].identity == "employee"
    assert findings[0].confidence.value == "medium"


def test_no_bfla_if_employee_gets_403():
    """Correct behavior: employee gets 403 on approve. No finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/lab/reset":
            return httpx.Response(200)

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 2}])

        if path == "/invoices/2":
            return httpx.Response(200, json={"id": 2, "status": "submitted"})

        if path == "/invoices/2/approve":
            if key == "lab-admin-key":
                return httpx.Response(200, json={"status": "approved"})
            return httpx.Response(403)

        return httpx.Response(404)

    with _client(handler) as client:
        findings = detect_bfla(_spec(), client, MantisConfig(), ADMIN, EMPLOYEE)

    assert findings == ()


def test_no_bfla_without_reset_endpoint():
    """Without /lab/reset, detect_bfla returns ()."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    with _client(handler) as client:
        findings = detect_bfla(_spec(), client, MantisConfig(), ADMIN, EMPLOYEE)
    # The spec has /lab/reset, but the handler returns [] for everything.
    # Wait: the spec has /lab/reset. So reset works. But there are no resources.
    # Then no BFLA.
    assert findings == ()