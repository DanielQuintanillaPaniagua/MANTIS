"""Invoice endpoints.

MK-002 step 5: this module contains three deliberate, documented
vulnerabilities. They are marked with V1, V2, V3 comments.

The correct version lives in git: `git show HEAD~1:lab/routes/invoices.py`
when you need to compare.

Do not "fix" these without updating:
- lab/VULNERABILITIES.md
- tests/integration/test_lab_vulnerabilities.py
- tests/integration/test_lab_invoices.py
"""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from lab.auth import get_current_user, get_db
from lab.models import Invoice, InvoiceStatus, Role, User

router = APIRouter(prefix="/invoices", tags=["invoices"])


def _row_to_invoice(row: sqlite3.Row) -> Invoice:
    return Invoice(
        id=row["id"],
        number=row["number"],
        branch_id=row["branch_id"],
        supplier=row["supplier"],
        total_cents=row["total_cents"],
        status=InvoiceStatus(row["status"]),
        created_at=row["created_at"],
    )


def _invoice_to_dict(inv: Invoice) -> dict:
    return {
        "id": inv.id,
        "number": inv.number,
        "branch_id": inv.branch_id,
        "supplier": inv.supplier,
        "total_cents": inv.total_cents,
        "status": inv.status.value,
        "created_at": inv.created_at,
    }


def _user_can_access_branch(user: User, branch_id: str) -> bool:
    """Legitimate authorization check. Still used by `submit`.

    Admin: all branches. Employee: own only.
    """
    if user.role is Role.ADMIN and user.branch_id is None:
        return True
    return user.branch_id == branch_id


def _load_invoice_or_404(conn: sqlite3.Connection, invoice_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id, number, branch_id, supplier, total_cents, status, created_at "
        "FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invoice not found",
        )
    return row


@router.get("")
def list_invoices(
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> list[dict]:
    """List invoices visible to the current user.

    NOT vulnerable. Filtering by branch is correct.
    V1 only affects GET /invoices/{invoice_id}.
    """
    if user.role is Role.ADMIN and user.branch_id is None:
        rows = conn.execute(
            "SELECT id, number, branch_id, supplier, total_cents, status, created_at "
            "FROM invoices ORDER BY id"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, number, branch_id, supplier, total_cents, status, created_at "
            "FROM invoices WHERE branch_id = ? ORDER BY id",
            (user.branch_id,),
        ).fetchall()

    return [_invoice_to_dict(_row_to_invoice(r)) for r in rows]


@router.get("/{invoice_id}")
def get_invoice(
    invoice_id: int,
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Return a single invoice.

    V1 — BOLA (Broken Object Level Authorization).

    The object-level authorization check is MISSING on purpose.
    Any authenticated user (admin or employee) can read ANY invoice by ID,
    regardless of branch.

    Correct behavior (in git HEAD~1):
        if not _user_can_access_branch(user, invoice.branch_id):
            raise HTTPException(403)
    """
    row = _load_invoice_or_404(conn, invoice_id)
    invoice = _row_to_invoice(row)

    # V1 — BOLA: authorization check removed on purpose.
    # Restore the following block to fix V1:
    #
    # if not _user_can_access_branch(user, invoice.branch_id):
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="You are not authorized to access this invoice",
    #     )

    return _invoice_to_dict(invoice)


@router.post("/{invoice_id}/submit")
def submit_invoice(
    invoice_id: int,
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Move invoice from draft -> submitted.

    NOT vulnerable. Authorization and transition are both checked.
    V2 and V3 only affect POST /invoices/{id}/approve.
    """
    row = _load_invoice_or_404(conn, invoice_id)
    invoice = _row_to_invoice(row)

    if not _user_can_access_branch(user, invoice.branch_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this invoice",
        )

    if invoice.status is not InvoiceStatus.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot submit invoice in status '{invoice.status.value}'",
        )

    conn.execute(
        "UPDATE invoices SET status = ? WHERE id = ?",
        (InvoiceStatus.SUBMITTED.value, invoice_id),
    )
    conn.commit()

    return {"id": invoice_id, "status": InvoiceStatus.SUBMITTED.value}


@router.post("/{invoice_id}/approve")
def approve_invoice(
    invoice_id: int,
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Move invoice from submitted -> approved.

    V2 — BFLA (Broken Function Level Authorization).
    V3 — State skip (invalid transition).

    Two checks are MISSING on purpose:
    - V2: the role check (admin only) is gone.
    - V3: the status check (submitted only) is gone.

    Correct behavior (in git HEAD~1):
        if user.role is not Role.ADMIN:
            raise HTTPException(403)
        ...
        if invoice.status is not InvoiceStatus.SUBMITTED:
            raise HTTPException(409)
    """
    # V2 — BFLA: role check removed on purpose.
    # Restore the following block to fix V2:
    #
    # if user.role is not Role.ADMIN:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Only admin can approve invoices",
    #     )

    row = _load_invoice_or_404(conn, invoice_id)
    invoice = _row_to_invoice(row)

    if not _user_can_access_branch(user, invoice.branch_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this invoice",
        )

    # V3 — State skip: transition check removed on purpose.
    # Restore the following block to fix V3:
    #
    # if invoice.status is not InvoiceStatus.SUBMITTED:
    #     raise HTTPException(
    #         status_code=status.HTTP_409_CONFLICT,
    #         detail=f"Cannot approve invoice in status '{invoice.status.value}'",
    #     )

    conn.execute(
        "UPDATE invoices SET status = ? WHERE id = ?",
        (InvoiceStatus.APPROVED.value, invoice_id),
    )
    conn.commit()

    return {"id": invoice_id, "status": InvoiceStatus.APPROVED.value}