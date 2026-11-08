"""Bridge between Django and the MANTIS engine.

This module is the ONLY place where dashboard code imports from mantis.
Everything else goes through the Scan model.

No business logic is duplicated. The engine does the work. We just
translate dataclasses to Django models.
"""

from __future__ import annotations

import datetime

from django.utils import timezone

from mantis.analysis.authorization import Identity, detect_bola
from mantis.analysis.models import Finding
from mantis.analysis.sequences import detect_bfla, detect_state_skip
from mantis.core.config import MantisConfig
from mantis.spec.errors import SpecError
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec
from mantis.transport.client import MantisClient

from .models import FindingRecord, Scan


def run_scan(
    *,
    scan: Scan,
    identity_a_key: str,
    identity_b_key: str,
) -> Scan:
    """Execute a scan and store findings.

    `scan` must already be persisted (has a pk) and configured with:
    - spec_path
    - base_url
    - identity_a
    - identity_b
    - options_json
    """
    scan.status = "running"
    scan.save(update_fields=["status"])

    try:
        findings = _execute_engine(scan, identity_a_key, identity_b_key)
    except SpecError as exc:
        scan.status = "failed"
        scan.error_message = f"{type(exc).__name__}: {exc}"
        scan.completed_at = timezone.now()
        scan.save()
        return scan
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = f"{type(exc).__name__}: {exc}"
        scan.completed_at = timezone.now()
        scan.save()
        return scan

    _store_findings(scan, findings)

    scan.status = "completed"
    scan.findings_count = len(findings)
    scan.completed_at = timezone.now()
    scan.save()
    return scan


def _execute_engine(scan: Scan, identity_a_key: str, identity_b_key: str) -> tuple[Finding, ...]:
    """Run the engine and return raw findings (dataclasses)."""
    options = scan.options_json or {}
    config_kwargs = {}
    if options.get("max_requests") is not None:
        config_kwargs["max_requests"] = options["max_requests"]
        config_kwargs["requests_per_minute"] = max(20, options["max_requests"])
    if options.get("privileged_operations"):
        config_kwargs["privileged_operations"] = tuple(options["privileged_operations"])
    if options.get("allowed_transitions"):
        config_kwargs["allowed_transitions"] = tuple(options["allowed_transitions"])
    config = MantisConfig(**config_kwargs)

    data = load_spec(scan.spec_path, config=config)
    spec = parse_spec(data)

    identity_a = Identity(scan.identity_a, identity_a_key, scan.base_url)
    identity_b = Identity(scan.identity_b, identity_b_key, scan.base_url)

    findings: list[Finding] = []
    with MantisClient(config) as client:
        findings.extend(detect_bola(spec, client, config, identity_a, identity_b))
        if options.get("sequences"):
            findings.extend(detect_bfla(spec, client, config, identity_a, identity_b))
            findings.extend(detect_state_skip(spec, client, config, identity_a))

    return tuple(findings)


def _store_findings(scan: Scan, findings: tuple[Finding, ...]) -> None:
    """Convert dataclass Findings to Django FindingRecord models."""
    records = []
    for f in findings:
        records.append(
            FindingRecord(
                scan=scan,
                finding_id=f.id,
                type=f.type.value,
                severity=f.severity.value,
                confidence=f.confidence.value,
                operation_method=f.operation_method,
                operation_path=f.operation_path,
                identity=f.identity,
                summary=f.summary,
                details=f.details,
                evidence_json=[
                    {
                        "description": e.description,
                        "method": e.method,
                        "url": e.url,
                        "status": e.status,
                        "response_size": e.response_size,
                        "error": e.error,
                    }
                    for e in f.evidence
                ],
                reproduction_json=list(f.reproduction),
            )
        )
    FindingRecord.objects.bulk_create(records)