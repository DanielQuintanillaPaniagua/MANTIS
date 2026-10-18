"""Verify that the lab seed is deterministic and matches MK-002.md."""

from lab.database import get_connection, reset_db
from lab.seed import BRANCHES, INVOICES, USERS, apply_seed


def _seeded_connection():
    conn = get_connection(":memory:")
    reset_db(conn)
    apply_seed(conn)
    return conn


def test_seed_inserts_two_branches():
    conn = _seeded_connection()
    rows = conn.execute("SELECT id, name FROM branches ORDER BY id").fetchall()
    assert [(r["id"], r["name"]) for r in rows] == BRANCHES


def test_seed_inserts_two_users():
    conn = _seeded_connection()
    rows = conn.execute(
        "SELECT id, username, role, api_key, branch_id FROM users ORDER BY id"
    ).fetchall()
    assert [(r["id"], r["username"], r["role"], r["api_key"], r["branch_id"]) for r in rows] == USERS


def test_seed_inserts_four_invoices():
    conn = _seeded_connection()
    rows = conn.execute(
        "SELECT id, number, branch_id, supplier, total_cents, status, created_at "
        "FROM invoices ORDER BY id"
    ).fetchall()
    got = [
        (r["id"], r["number"], r["branch_id"], r["supplier"],
         r["total_cents"], r["status"], r["created_at"])
        for r in rows
    ]
    assert got == INVOICES


def test_seed_is_idempotent():
    """Two resets + seeds must produce identical data."""
    conn1 = _seeded_connection()
    conn2 = _seeded_connection()

    for table in ("branches", "users", "invoices"):
        rows1 = conn1.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        rows2 = conn2.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        assert [tuple(r) for r in rows1] == [tuple(r) for r in rows2]


def test_invoice_status_check_rejects_invalid_value():
    import sqlite3
    import pytest

    conn = _seeded_connection()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO invoices (id, number, branch_id, supplier, total_cents, status, created_at) "
            "VALUES (99, 'FAC-099', 'S001', 'X', 100, 'invalid', '2026-01-01T00:00:00Z')"
        )


def test_foreign_key_enforced():
    import sqlite3
    import pytest

    conn = _seeded_connection()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO invoices (id, number, branch_id, supplier, total_cents, status, created_at) "
            "VALUES (99, 'FAC-099', 'S999', 'X', 100, 'draft', '2026-01-01T00:00:00Z')"
        )