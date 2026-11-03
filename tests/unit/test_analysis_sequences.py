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
from mantis.analysis.sequences import detect_bfla, detect_state_skip
from mantis.analysis.sequences import detect_bfla, detect_state_skip


ADMIN = Identity("admin", "lab-admin-key", "http://127.0.0.1:8000")
EMPLOYEE = Identity("employee", "lab-employee-key", "http://127.0.0.1:8000")


def _config() -> MantisConfig:
    """Config with high limits and privileged operations for BFLA tests."""
    return MantisConfig(
        max_requests=200,
        requests_per_minute=200,
        privileged_operations=("approve",),
    )


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


def _client(handler, config: MantisConfig) -> MantisClient:
    return MantisClient(config, transport=httpx.MockTransport(handler))


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

    config = _config()
    with _client(handler, config) as client:
        findings = detect_bfla(_spec(), client, config, ADMIN, EMPLOYEE)

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

    config = _config()
    with _client(handler, config) as client:
        findings = detect_bfla(_spec(), client, config, ADMIN, EMPLOYEE)

    assert findings == ()


def test_no_bfla_without_privileged_operations():
    """Without privileged_operations, detect_bfla returns () even if everything else works."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    config = MantisConfig(
        max_requests=200,
        requests_per_minute=200,
        privileged_operations=(),  # empty
    )
    with _client(handler, config) as client:
        findings = detect_bfla(_spec(), client, config, ADMIN, EMPLOYEE)

    assert findings == ()


def test_no_bfla_without_reset_endpoint():
    """Without /lab/reset in spec, detect_bfla returns ()."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    # Spec without /lab/reset
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
    spec_without_reset = ApiSpec(
        openapi_version="3.1.0",
        title="Test",
        version="1.0.0",
        operations=(read_op, approve_op),
    )

    config = _config()
    with _client(handler, config) as client:
        findings = detect_bfla(spec_without_reset, client, config, ADMIN, EMPLOYEE)

    assert findings == ()
def test_detects_state_skip_when_admin_approves_draft():
    """Admin approves a draft invoice directly (V3)."""

    state = {"status": "draft"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        key = request.headers.get("x-api-key", "")

        if path == "/lab/reset":
            state["status"] = "draft"
            return httpx.Response(200, json={"status": "reset"})

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}])

        if path == "/invoices/1":
            return httpx.Response(200, json={"id": 1, "status": state["status"]})

        if path == "/invoices/1/submit":
            if state["status"] == "draft":
                state["status"] = "submitted"
                return httpx.Response(200, json={"status": "submitted"})
            return httpx.Response(409)

        if path == "/invoices/1/approve":
            if state["status"] == "draft":
                # V3: skip submitted
                state["status"] = "approved"
                return httpx.Response(200, json={"status": "approved"})
            if state["status"] == "submitted":
                state["status"] = "approved"
                return httpx.Response(200, json={"status": "approved"})
            return httpx.Response(409)

        return httpx.Response(404)

    spec = _spec_with_state_ops()
    config = _config()
    with _client(handler, config) as client:
        findings = detect_state_skip(spec, client, config, ADMIN)

    assert len(findings) == 1
    assert findings[0].type.value == "STATE_SKIP"
    assert findings[0].confidence.value == "medium"


def _spec_with_state_ops() -> ApiSpec:
    """Spec with reset, GET, submit, and approve."""
    reset_op = Operation(method=HttpMethod.POST, path="/lab/reset")
    read_op = Operation(
        method=HttpMethod.GET,
        path="/invoices/{invoice_id}",
        parameters=(
            Parameter(name="invoice_id", location=ParameterLocation.PATH, required=True),
        ),
    )
    submit_op = Operation(
        method=HttpMethod.POST,
        path="/invoices/{invoice_id}/submit",
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
        operations=(reset_op, read_op, submit_op, approve_op),
    )


def test_no_state_skip_if_approve_requires_submitted():
    """Correct behavior: approve on draft returns 409. No finding."""

    state = {"status": "draft"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/lab/reset":
            state["status"] = "draft"
            return httpx.Response(200)

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}])

        if path == "/invoices/1":
            return httpx.Response(200, json={"id": 1, "status": state["status"]})

        if path == "/invoices/1/submit":
            if state["status"] == "draft":
                state["status"] = "submitted"
                return httpx.Response(200, json={"status": "submitted"})
            return httpx.Response(409)

        if path == "/invoices/1/approve":
            if state["status"] == "submitted":
                state["status"] = "approved"
                return httpx.Response(200, json={"status": "approved"})
            return httpx.Response(409)  # Correct: rejects draft

        return httpx.Response(404)

    spec = _spec_with_state_ops()
    config = _config()
    with _client(handler, config) as client:
        findings = detect_state_skip(spec, client, config, ADMIN)

    assert findings == ()
def test_state_skip_with_allowed_transitions_ignores_order():
    """If allowed_transitions is declared, spec order does not matter."""

    state = {"status": "draft"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/lab/reset":
            state["status"] = "draft"
            return httpx.Response(200)

        if path == "/invoices":
            return httpx.Response(200, json=[{"id": 1}])

        if path == "/invoices/1":
            return httpx.Response(200, json={"id": 1, "status": state["status"]})

        if path == "/invoices/1/submit":
            if state["status"] == "draft":
                state["status"] = "submitted"
                return httpx.Response(200)
            return httpx.Response(409)

        if path == "/invoices/1/approve":
            if state["status"] == "submitted":
                state["status"] = "approved"
                return httpx.Response(200)
            # V3: approve draft directly
            if state["status"] == "draft":
                state["status"] = "approved"
                return httpx.Response(200)
            return httpx.Response(409)

        return httpx.Response(404)

    # Spec with approve BEFORE submit (worst case for order-based heuristic)
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
    submit_op = Operation(
        method=HttpMethod.POST,
        path="/invoices/{invoice_id}/submit",
        parameters=(
            Parameter(name="invoice_id", location=ParameterLocation.PATH, required=True),
        ),
    )
    reset_op = Operation(method=HttpMethod.POST, path="/lab/reset")
    spec = ApiSpec(
        openapi_version="3.1.0",
        title="Test",
        version="1.0.0",
        operations=(reset_op, read_op, approve_op, submit_op),  # approve BEFORE submit
    )

    config = MantisConfig(
        max_requests=200,
        requests_per_minute=200,
        allowed_transitions=("status:draft->submitted", "status:submitted->approved"),
    )
    with _client(handler, config) as client:
        findings = detect_state_skip(spec, client, config, ADMIN)

    # With allowed_transitions, approve is correctly identified as state skip
    # even though it appears first in the spec.
    assert len(findings) == 1
    assert findings[0].type.value == "STATE_SKIP"
    assert "/approve" in findings[0].operation_path