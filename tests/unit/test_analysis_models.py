"""Unit tests for analysis models."""

import pytest

from mantis.analysis.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)


def test_finding_type_values():
    assert FindingType.BOLA == "BOLA"
    assert FindingType.BFLA == "BFLA"
    assert FindingType.STATE_SKIP == "STATE_SKIP"


def test_severity_values():
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM == "medium"
    assert Severity.LOW == "low"


def test_confidence_values():
    assert Confidence.HIGH == "high"
    assert Confidence.MEDIUM == "medium"
    assert Confidence.LOW == "low"


def test_evidence_is_frozen():
    e = Evidence(
        description="admin reads invoice 1",
        method="GET",
        url="http://127.0.0.1:8000/invoices/1",
        status=200,
    )
    with pytest.raises(Exception):
        e.status = 500  # type: ignore[misc]


def test_finding_minimal():
    f = Finding(
        id="BOLA-001",
        type=FindingType.BOLA,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        operation_method="GET",
        operation_path="/invoices/{invoice_id}",
        identity="employee",
        summary="Employee can read invoice from another branch",
        details="Employee (branch S001) read invoice 3 (branch S002).",
    )
    assert f.id == "BOLA-001"
    assert f.evidence == ()
    assert f.reproduction == ()


def test_finding_with_evidence_and_reproduction():
    ev1 = Evidence(
        description="employee reads own invoice",
        method="GET",
        url="http://127.0.0.1:8000/invoices/1",
        status=200,
    )
    ev2 = Evidence(
        description="employee reads other branch invoice",
        method="GET",
        url="http://127.0.0.1:8000/invoices/3",
        status=200,
    )
    f = Finding(
        id="BOLA-001",
        type=FindingType.BOLA,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        operation_method="GET",
        operation_path="/invoices/{invoice_id}",
        identity="employee",
        summary="BOLA",
        details="...",
        evidence=(ev1, ev2),
        reproduction=(
            "1. Use X-API-Key: lab-employee-key",
            "2. GET /invoices/3",
            "3. Expect 403, got 200",
        ),
    )
    assert len(f.evidence) == 2
    assert len(f.reproduction) == 3


def test_finding_to_dict():
    f = Finding(
        id="BOLA-001",
        type=FindingType.BOLA,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        operation_method="GET",
        operation_path="/invoices/{invoice_id}",
        identity="employee",
        summary="BOLA",
        details="...",
    )
    d = f.to_dict()
    assert d["id"] == "BOLA-001"
    assert d["type"] == "BOLA"
    assert d["severity"] == "high"
    assert d["operation_method"] == "GET"