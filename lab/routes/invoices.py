"""Invoice endpoints. Legitimate authorization. No planted vulnerability here.

This module establishes the CORRECT behavior. In step 5 (V1, V2, V3),
we will deliberately break specific checks to plant vulnerabilities.
That is why this file must be clear and correct now.
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
    """Legitimate authorization check. Admin: all branches. Employee: own only."""
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

    Admin: all invoices.
    Employee: only invoices in their assigned branch.
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
    """Return a single invoice. Object-level authorization is enforced."""
    row = _load_invoice_or_404(conn, invoice_id)
    invoice = _row_to_invoice(row)

    if not _user_can_access_branch(user, invoice.branch_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this invoice",
        )

    return _invoice_to_dict(invoice)


@router.post("/{invoice_id}/submit")
def submit_invoice(
    invoice_id: int,
    user: User = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Move invoice from draft -> submitted.

    - Object authorization is enforced (employee only own branch).
    - Transition is validated (only draft can be submitted).
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
    """Move invoice from submitted -> approved. Admin only.

    - Role authorization is enforced (admin only).
    - Object authorization is enforced (admin: all branches).
    - Transition is validated (only submitted can be approved).
    """
    if user.role is not Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin can approve invoices",
        )

    row = _load_invoice_or_404(conn, invoice_id)
    invoice = _row_to_invoice(row)

    if not _user_can_access_branch(user, invoice.branch_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this invoice",
        )

    if invoice.status is not InvoiceStatus.SUBMITTED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot approve invoice in status '{invoice.status.value}'",
        )

    conn.execute(
        "UPDATE invoices SET status = ? WHERE id = ?",
        (InvoiceStatus.APPROVED.value, invoice_id),
    )
    conn.commit()

    return {"id": invoice_id, "status": InvoiceStatus.APPROVED.value}