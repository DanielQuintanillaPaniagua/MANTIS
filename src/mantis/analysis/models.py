"""Models for analysis findings and evidence.

A Finding is the unit of output from the analysis engine. It must be
self-contained: enough to understand the issue and reproduce it
without re-running the whole scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FindingType(StrEnum):
    """Known categories of findings."""

    BOLA = "BOLA"
    BFLA = "BFLA"
    STATE_SKIP = "STATE_SKIP"


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Evidence:
    """One request/response pair that supports a finding.

    Intentionally lightweight. It does not store the full response body
    unless explicitly requested (privacy, size).
    """

    description: str
    method: str
    url: str
    status: int
    response_size: int = 0
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    """A single finding produced by the analysis engine.

    Fields are chosen so that the finding is understandable without
    re-reading the spec or re-running the scan.
    """

    id: str
    type: FindingType
    severity: Severity
    confidence: Confidence
    operation_method: str
    operation_path: str
    identity: str
    summary: str
    details: str
    evidence: tuple[Evidence, ...] = ()
    reproduction: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON output."""
        from dataclasses import asdict

        return asdict(self)