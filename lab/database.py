"""SQLite access layer for the MANTIS lab.

Explicit SQL. No ORM. The schema is tiny and stable.

The DB lives at lab/lab.db by default. Tests can override with
:memory: to avoid touching the file.
"""

import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent / "lab.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS branches (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id        TEXT PRIMARY KEY,
    username  TEXT NOT NULL UNIQUE,
    role      TEXT NOT NULL CHECK (role IN ('admin', 'employee')),
    api_key   TEXT NOT NULL UNIQUE,
    branch_id TEXT,
    FOREIGN KEY (branch_id) REFERENCES branches(id)
);

CREATE TABLE IF NOT EXISTS invoices (
    id          INTEGER PRIMARY KEY,
    number      TEXT NOT NULL UNIQUE,
    branch_id   TEXT NOT NULL,
    supplier    TEXT NOT NULL,
    total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
    status      TEXT NOT NULL CHECK (status IN ('draft', 'submitted', 'approved')),
    created_at  TEXT NOT NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id)
);
"""


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection with row access by column name.

    For tests, pass ':memory:' to avoid touching the file.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they do not exist."""
    conn.executescript(SCHEMA)
    conn.commit()


def reset_db(conn: sqlite3.Connection) -> None:
    """Drop all data and recreate tables from scratch.

    This does NOT insert seed data. Call seed.apply_seed(conn) after.
    """
    conn.executescript(
        """
        DROP TABLE IF EXISTS invoices;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS branches;
        """
    )
    init_db(conn)