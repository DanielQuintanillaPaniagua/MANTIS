"""Branch visibility tests. Legitimate authorization, no vulnerability."""

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


def test_branches_without_api_key_returns_401(client):
    response = client.get("/branches")
    assert response.status_code == 401


def test_admin_sees_all_branches(client):
    response = client.get("/branches", headers={"X-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    ids = {b["id"] for b in body}
    assert ids == {"S001", "S002"}


def test_employee_sees_only_own_branch(client):
    response = client.get("/branches", headers={"X-API-Key": EMPLOYEE_KEY})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == "S001"
    assert body[0]["name"] == "Norte"