"""Authentication and identity resolution for the MANTIS lab.

API key travels in the X-API-Key header. No JWT. No OAuth. The lab
only needs to know who is calling and what role they have.
"""

import sqlite3

from fastapi import Depends, Header, HTTPException, status

from lab.database import get_connection
from lab.models import Role, User


def get_db() -> sqlite3.Connection:
    """FastAPI dependency: open a DB connection per request."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


def get_current_user(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    conn: sqlite3.Connection = Depends(get_db),
) -> User:
    """Resolve the calling user from the X-API-Key header.

    Missing or unknown key -> 401.
    """
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    row = conn.execute(
        "SELECT id, username, role, api_key, branch_id FROM users WHERE api_key = ?",
        (x_api_key,),
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return User(
        id=row["id"],
        username=row["username"],
        role=Role(row["role"]),
        api_key=row["api_key"],
        branch_id=row["branch_id"],
    )