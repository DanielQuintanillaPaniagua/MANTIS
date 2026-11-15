"""Result of an analysis pass."""

from dataclasses import dataclass, field
from enum import StrEnum

from mantis.analysis.models import Finding


class AssessmentState(StrEnum):
    """Overall state of the assessment."""
    CONFIRMED = "CONFIRMED"
    NOT_FOUND = "NOT_FOUND"
    OMITTED = "OMITTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ScanResult:
    """Outcome of an analysis run."""
    
    state: AssessmentState
    findings: tuple[Finding, ...] = ()
    reason: str | None = None  # Por qué se omitió o fue inconcluso