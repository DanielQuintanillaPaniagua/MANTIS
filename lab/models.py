"""Domain models for the MANTIS lab.

These are plain dataclasses. No ORM. The lab is small enough that
explicit SQL in database.py is clearer than any abstraction.
"""

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    """User roles in the lab."""

    ADMIN = "admin"
    EMPLOYEE = "employee"


class InvoiceStatus(StrEnum):
    """Invoice states. Only the transitions in MK-002.md are valid."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"


@dataclass(frozen=True)
class User:
    id: str
    username: str
    role: Role
    api_key: str
    branch_id: str | None  # None = access to all branches (admin)


@dataclass(frozen=True)
class Branch:
    id: str
    name: str


@dataclass(frozen=True)
class Invoice:
    id: int
    number: str
    branch_id: str
    supplier: str
    total_cents: int
    status: InvoiceStatus
    created_at: str  # ISO 8601 UTC, fixed in seed