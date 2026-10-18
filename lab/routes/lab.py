"""Lab utilities. Not production endpoints."""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from lab.auth import get_current_user, get_db
from lab.models import Role, User
from lab.seed import apply_seed
from lab.database import reset_db

router = APIRouter(prefix="/lab", tags=["lab"])


@router.post("/reset")
def lab_reset(
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Restore the lab database to its deterministic seed. Admin only."""
    if user.role is not Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin can reset the lab",
        )

    reset_db(conn)
    apply_seed(conn)

    return {"status": "reset", "message": "Lab database restored to seed"}