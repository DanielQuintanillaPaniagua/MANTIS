"""Authentication tests: X-API-Key, /me."""

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


def test_me_without_api_key_returns_401(client):
    response = client.get("/me")
    assert response.status_code == 401


def test_me_with_invalid_api_key_returns_401(client):
    response = client.get("/me", headers={"X-API-Key": "nope"})
    assert response.status_code == 401


def test_me_with_admin_key_returns_admin_identity(client):
    response = client.get("/me", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "U001"
    assert body["username"] == "admin"
    assert body["role"] == "admin"
    assert body["branch_id"] is None


def test_me_with_employee_key_returns_employee_identity(client):
    response = client.get("/me", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "U002"
    assert body["username"] == "empleado"
    assert body["role"] == "employee"
    assert body["branch_id"] == "S001"