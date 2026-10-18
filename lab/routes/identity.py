"""Identity and branch visibility endpoints.

These endpoints are legitimate: no planted vulnerability lives here.
They establish the pattern for authorization that later steps reuse.
"""

from fastapi import APIRouter, Depends

from lab.auth import get_current_user, get_db
from lab.models import Branch, Role, User

router = APIRouter(tags=["identity"])


@router.get("/me")
def read_me(user: User = Depends(get_current_user)) -> dict:
    """Return the authenticated user's identity and role."""
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role.value,
        "branch_id": user.branch_id,
    }


@router.get("/branches")
def list_branches(
    user: User = Depends(get_current_user),
    conn=Depends(get_db),
) -> list[dict]:
    """List branches visible to the current user.

    Admin (branch_id is None) sees all branches.
    Employee sees only their assigned branch.
    """
    if user.role is Role.ADMIN and user.branch_id is None:
        rows = conn.execute("SELECT id, name FROM branches ORDER BY id").fetchall()
    else:
        rows = conn.execute(
            "SELECT id, name FROM branches WHERE id = ? ORDER BY id",
            (user.branch_id,),
        ).fetchall()

    return [
        Branch(id=r["id"], name=r["name"]).__dict__
        for r in rows
    ]