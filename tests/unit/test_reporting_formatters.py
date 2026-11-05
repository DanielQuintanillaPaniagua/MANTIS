"""Unit tests for reporting formatters."""

import json

from mantis.analysis.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from mantis.reporting.formatters import (
    format_findings_json,
    format_findings_markdown,
)


def _sample_finding() -> Finding:
    return Finding(
        id="BOLA-001",
        type=FindingType.BOLA,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        operation_method="GET",
        operation_path="/invoices/{invoice_id}",
        identity="employee",
        summary="Employee can read invoice from another branch",
        details="Employee (S001) read invoice 3 (S002).",
        evidence=(
            Evidence(
                description="admin reads invoice 3",
                method="GET",
                url="http://127.0.0.1:8000/invoices/3",
                status=200,
            ),
            Evidence(
                description="employee reads invoice 3",
                method="GET",
                url="http://127.0.0.1:8000/invoices/3",
                status=200,
            ),
        ),
        reproduction=(
            "Use identity employee",
            "GET /invoices/3",
            "Expected 403, got 200",
        ),
    )


# --- JSON ---

def test_json_empty():
    result = format_findings_json((), spec_title="Test")
    data = json.loads(result)
    assert data["spec"] == "Test"
    assert data["findings_count"] == 0
    assert data["findings"] == []


def test_json_with_finding():
    result = format_findings_json((_sample_finding(),), spec_title="Test")
    data = json.loads(result)
    assert data["spec"] == "Test"
    assert data["findings_count"] == 1
    f = data["findings"][0]
    assert f["id"] == "BOLA-001"
    assert f["type"] == "BOLA"
    assert f["severity"] == "high"
    assert f["confidence"] == "high"
    assert len(f["evidence"]) == 2
    assert len(f["reproduction"]) == 3


def test_json_is_valid_utf8():
    f = _sample_finding()
    # Simulate unicode in summary
    f_unicode = Finding(
        id=f.id,
        type=f.type,
        severity=f.severity,
        confidence=f.confidence,
        operation_method=f.operation_method,
        operation_path=f.operation_path,
        identity=f.identity,
        summary="Empleado accede a factura ajena (año 2026)",
        details=f.details,
    )
    result = format_findings_json((f_unicode,), spec_title="Test")
    data = json.loads(result)
    assert "año" in data["findings"][0]["summary"]


# --- Markdown ---

def test_markdown_empty():
    result = format_findings_markdown((), spec_title="Test")
    assert "# MANTIS Scan Report: Test" in result
    assert "**Findings:** 0" in result
    assert "No findings." in result


def test_markdown_with_finding():
    result = format_findings_markdown((_sample_finding(),), spec_title="Test")
    assert "# MANTIS Scan Report: Test" in result
    assert "**Findings:** 1" in result
    assert "## Summary" in result
    assert "| BOLA-001 |" in result
    assert "## Details" in result
    assert "### BOLA-001" in result
    assert "**Type:** BOLA" in result
    assert "**Summary:**" in result
    assert "**Evidence:**" in result
    assert "**Reproduction:**" in result


def test_markdown_contains_evidence_urls():
    result = format_findings_markdown((_sample_finding(),), spec_title="Test")
    assert "http://127.0.0.1:8000/invoices/3" in result
    assert "admin reads invoice 3" in result
    assert "employee reads invoice 3" in result


def test_markdown_without_spec_title():
    result = format_findings_markdown((_sample_finding(),), spec_title=None)
    assert "(unknown spec)" in result