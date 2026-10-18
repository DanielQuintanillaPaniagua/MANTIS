"""Tests for POST /lab/reset."""

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


def test_reset_without_api_key_returns_401(client):
    response = client.post("/lab/reset")
    assert response.status_code == 401


def test_reset_with_employee_returns_403(client):
    response = client.post("/lab/reset", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 403


def test_reset_with_admin_restores_seed(client):
    # Mutate invoice 1 to approved
    client.post("/invoices/1/submit", headers={"X-API-Key": ADMIN_KEY})
    client.post("/invoices/1/approve", headers={"X-API-Key": ADMIN_KEY})

    # Verify it changed
    before = client.get("/invoices/1", headers={"X-API-Key": ADMIN_KEY})
    assert before.json()["status"] == "approved"

    # Reset
    response = client.post("/lab/reset", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 200

    # Verify invoice 1 is back to draft
    after = client.get("/invoices/1", headers={"X-API-Key": ADMIN_KEY})
    assert after.json()["status"] == "draft"