"""Invoice endpoints. All legitimate behavior. No vulnerability here."""

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


# --- GET /invoices ---

def test_list_invoices_without_api_key_returns_401(client):
    response = client.get("/invoices")
    assert response.status_code == 401


def test_admin_lists_all_invoices(client):
    response = client.get("/invoices", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 4
    assert {inv["id"] for inv in body} == {1, 2, 3, 4}


def test_employee_lists_only_own_branch_invoices(client):
    response = client.get("/invoices", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert {inv["id"] for inv in body} == {1, 2}
    assert all(inv["branch_id"] == "S001" for inv in body)


# --- GET /invoices/{id} ---

def test_admin_reads_any_invoice(client):
    response = client.get("/invoices/3", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    assert response.json()["id"] == 3
    assert response.json()["branch_id"] == "S002"


def test_employee_reads_own_invoice(client):
    response = client.get("/invoices/1", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    assert response.json()["id"] == 1





def test_get_unknown_invoice_returns_404(client):
    response = client.get("/invoices/999", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 404


# --- POST /invoices/{id}/submit ---

def test_submit_draft_invoice_succeeds(client):
    response = client.post(
        "/invoices/1/submit", headers={"X-API-Key": EMPLOYEE_KEY}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "submitted"


def test_submit_already_submitted_returns_409(client):
    response = client.post(
        "/invoices/2/submit", headers={"X-API-Key": EMPLOYEE_KEY}
    )
    assert response.status_code == 409


# --- POST /invoices/{id}/approve ---

def test_admin_approves_submitted_invoice(client):
    response = client.post(
        "/invoices/2/approve", headers={"X-API-Key": ADMIN_KEY}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

def test_admin_can_approve_submitted_invoice_after_reset(client):
    """Sanity: the correct approve path still works with the right user and state."""
    # Reset first because other tests may have mutated invoice 2.
    client.post("/lab/reset", headers={"X-API-Key": ADMIN_KEY})

    response = client.post(
        "/invoices/2/approve", headers={"X-API-Key": ADMIN_KEY}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    