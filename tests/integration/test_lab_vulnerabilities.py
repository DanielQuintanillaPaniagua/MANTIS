"""Tests that demonstrate the planted vulnerabilities exist.

These tests PASS because the lab is vulnerable on purpose.
In MK-005, MANTIS must find exactly these three cases.

If MANTIS ever finds something not listed here, it is a false positive.
If MANTIS misses one of these, it is a false negative.
"""

import pytest
from fastapi.testclient import TestClient

from lab.app import app
from lab.database import get_connection, reset_db
from lab.seed import apply_seed


ADMIN_KEY = "lab-admin-key"
EMPLOYEE_KEY = "lab-employee-key"


@pytest.fixture
def client():
    conn = get_connection()
    reset_db(conn)
    apply_seed(conn)
    conn.close()
    return TestClient(app)


# --- V1: BOLA (Broken Object Level Authorization) ---

def test_v1_employee_can_read_invoice_from_other_branch(client):
    """V1 — BOLA.

    Employee (U002, assigned to S001) reads invoice 3 (branch S002).
    Correct behavior: 403.
    Vulnerable behavior: 200 with the invoice data.
    """
    response = client.get("/invoices/3", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == 3
    assert body["branch_id"] == "S002"
    # The leak: employee sees a branch they should not access.


def test_v1_listing_still_filters_correctly(client):
    """V1 is object-level only. The listing must still be filtered.

    This guards against accidental regression: if someone "fixes" V1
    by breaking the listing, this test will fail.
    """
    response = client.get("/invoices", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    body = response.json()
    assert {inv["id"] for inv in body} == {1, 2}
    assert all(inv["branch_id"] == "S001" for inv in body)


# --- V2: BFLA (Broken Function Level Authorization) ---

def test_v2_employee_can_approve_invoice(client):
    """V2 — BFLA.

    Employee approves invoice 2 (S001, submitted).
    The invoice is in the employee's own branch, so V1 does not apply.
    Correct behavior: 403 (admin only).
    Vulnerable behavior: 200, and the DB reflects the change.
    """
    response = client.post(
        "/invoices/2/approve", headers={"X-API-Key": EMPLOYEE_KEY}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    # Verify the effect persisted, not just the HTTP response.
    check = client.get("/invoices/2", headers={"X-API-Key": ADMIN_KEY})
    assert check.json()["status"] == "approved"


# --- V3: State skip (invalid transition) ---

def test_v3_admin_can_approve_draft_invoice(client):
    """V3 — State skip.

    Admin approves invoice 1 (S001, draft), skipping submitted.
    The admin is authorized (no V2 here), and the invoice is in
    scope (no V1 here). Only the transition rule is violated.
    Correct behavior: 409.
    Vulnerable behavior: 200, and the DB reflects the change.
    """
    response = client.post(
        "/invoices/1/approve", headers={"X-API-Key": ADMIN_KEY}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    check = client.get("/invoices/1", headers={"X-API-Key": ADMIN_KEY})
    assert check.json()["status"] == "approved"


def test_v3_submit_still_validates_state(client):
    """V3 only affects approve, not submit.

    Submit must still reject invoices that are not in draft.
    """
    response = client.post(
        "/invoices/2/submit", headers={"X-API-Key": EMPLOYEE_KEY}
    )
    assert response.status_code == 409