"""Deterministic seed data for the MANTIS lab.

Run with: python -m lab.seed

The seed is fixed. No datetime.now(). No randomness. Two runs must
produce byte-identical databases.
"""

from lab.database import DEFAULT_DB_PATH, get_connection, init_db, reset_db

BRANCHES = [
    ("S001", "Norte"),
    ("S002", "Sur"),
]

USERS = [
    # id, username, role, api_key, branch_id
    ("U001", "admin", "admin", "lab-admin-key", None),
    ("U002", "empleado", "employee", "lab-employee-key", "S001"),
]

INVOICES = [
    # id, number, branch_id, supplier, total_cents, status, created_at
    (1, "FAC-001", "S001", "Proveedor Norte A", 1250, "draft", "2026-01-01T10:00:00Z"),
    (2, "FAC-002", "S001", "Proveedor Norte B", 9999, "submitted", "2026-01-02T10:00:00Z"),
    (3, "FAC-003", "S002", "Proveedor Sur A", 125000, "draft", "2026-01-03T10:00:00Z"),
    (4, "FAC-004", "S002", "Proveedor Sur B", 4250, "submitted", "2026-01-04T10:00:00Z"),
]


def apply_seed(conn) -> None:
    """Insert seed rows into an already-initialized DB."""
    conn.executemany(
        "INSERT INTO branches (id, name) VALUES (?, ?)",
        BRANCHES,
    )
    conn.executemany(
        "INSERT INTO users (id, username, role, api_key, branch_id) VALUES (?, ?, ?, ?, ?)",
        USERS,
    )
    conn.executemany(
        """
        INSERT INTO invoices (id, number, branch_id, supplier, total_cents, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        INVOICES,
    )
    conn.commit()


def seed_database(db_path=DEFAULT_DB_PATH) -> None:
    """Reset the DB and apply the seed. Idempotent."""
    conn = get_connection(db_path)
    try:
        reset_db(conn)
        apply_seed(conn)
    finally:
        conn.close()


def main() -> None:
    seed_database()
    print(f"Seeded database at {DEFAULT_DB_PATH}")


if __name__ == "__main__":
    main()