"""Formatters for findings.

Pure functions: input = findings + metadata, output = string.
No I/O. No side effects. Easy to test.
"""

from __future__ import annotations

import json

from mantis.analysis.models import Finding


def format_findings_json(
    findings: tuple[Finding, ...],
    spec_title: str | None = None,
) -> str:
    """Format findings as an indented JSON array.

    The `spec_title` parameter is kept for API consistency but does not
    change the output: the JSON is always a plain array of findings.
    This makes the output easy to parse with `json.loads(...)` and
    preserves backward compatibility with existing tests.
    """
    return json.dumps(
        [f.to_dict() for f in findings],
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def format_findings_markdown(
    findings: tuple[Finding, ...],
    spec_title: str | None = None,
) -> str:
    """Format findings as Markdown.

    Produces a summary table followed by detailed sections per finding.
    Empty findings produces a short "no findings" report.
    """
    lines: list[str] = []

    title = spec_title or "(unknown spec)"
    lines.append(f"# MANTIS Scan Report: {title}")
    lines.append("")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| ID | Type | Severity | Confidence | Operation | Identity |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f.id} | {f.type.value} | {f.severity.value} | "
            f"{f.confidence.value} | {f.operation_method} {f.operation_path} | "
            f"{f.identity} |"
        )
    lines.append("")

    # Detailed sections
    lines.append("## Details")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.id}")
        lines.append("")
        lines.append(f"- **Type:** {f.type.value}")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **Confidence:** {f.confidence.value}")
        lines.append(f"- **Operation:** `{f.operation_method} {f.operation_path}`")
        lines.append(f"- **Identity:** {f.identity}")
        lines.append("")
        lines.append(f"**Summary:** {f.summary}")
        lines.append("")
        lines.append(f"**Details:** {f.details}")
        lines.append("")

        if f.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            for ev in f.evidence:
                lines.append(f"- {ev.description}")
                lines.append(f"  - `{ev.method} {ev.url}` → {ev.status}")
            lines.append("")

        if f.reproduction:
            lines.append("**Reproduction:**")
            lines.append("")
            for step in f.reproduction:
                lines.append(f"1. {step}")
            lines.append("")

    return "\n".join(lines)