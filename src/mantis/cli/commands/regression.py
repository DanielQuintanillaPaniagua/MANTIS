"""`mantis regression run <baseline>` command.

Re-runs a scan using the parameters saved in a baseline, then compares
the current findings with the expected ones.

Outcomes:
- "still present": expected finding, still detected.
- "corrected": expected finding, no longer detected (vulnerability fixed).
- "new": detected finding, not in baseline (regression or new vuln).

Exit codes:
    0 -> everything as expected (all present, 0 new)
    1 -> differences (corrected or new)
    2 -> argument error
    4 -> spec/baseline error
    5 -> evidence write error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

from mantis.analysis.authorization import Identity, detect_bola
from mantis.analysis.sequences import detect_bfla, detect_state_skip
from mantis.cli.commands.ping import DEFAULT_LOG_PATH
from mantis.core.config import MantisConfig
from mantis.reporting.formatters import (
    format_findings_json,
    format_findings_markdown,
)
from mantis.spec.errors import SpecError
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec
from mantis.transport.client import MantisClient, RateLimitExceeded
from mantis.transport.log import EvidenceWriteError, RequestLogWriter
from mantis.transport.policy import TargetNotAllowed


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "regression",
        help="Compare a scan against a saved baseline.",
        description="Re-run a scan and compare with a baseline.",
    )
    parser_sub = parser.add_subparsers(dest="regression_command", metavar="SUBCOMMAND")

    run_parser = parser_sub.add_parser(
        "run",
        help="Run regression against a baseline file.",
        description="Re-run a scan using a baseline and compare.",
    )
    run_parser.add_argument("baseline", type=Path, help="Path to the baseline JSON")
    run_parser.add_argument(
        "--identity",
        action="append",
        required=True,
        metavar="NAME:KEY",
        help=(
            "Identity to test. Repeatable. Order must match the baseline. "
            "Example: --identity admin:lab-admin-key --identity employee:lab-employee-key"
        ),
    )
    run_parser.add_argument(
        "--format",
        choices=("human", "json", "markdown"),
        default="human",
        help="Output format (default: human).",
    )
    run_parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"Evidence log path (default: {DEFAULT_LOG_PATH}).",
    )
    run_parser.add_argument(
        "--no-log",
        action="store_true",
        help="Do not write evidence to disk.",
    )
    run_parser.set_defaults(func=run)


def _parse_identities(pairs: list[str], base_url: str) -> list[Identity]:
    result: list[Identity] = []
    for pair in pairs:
        if ":" not in pair:
            raise ValueError(f"Invalid identity (expected NAME:KEY): {pair!r}")
        name, _, key = pair.partition(":")
        name = name.strip()
        key = key.strip()
        if not name or not key:
            raise ValueError(f"Invalid identity (empty name or key): {pair!r}")
        result.append(Identity(name=name, api_key=key, base_url=base_url))
    return result


def run(args: argparse.Namespace) -> int:
    """Execute `mantis regression run`."""
    if getattr(args, "regression_command", None) != "run":
        print("error: missing subcommand. Try: mantis regression run <baseline>", file=sys.stderr)
        return 2

    baseline = _load_baseline(args.baseline)
    if baseline is None:
        return 4

    try:
        identities = _parse_identities(args.identity, baseline["options"]["base_url"])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if len(identities) < 2:
        print("error: at least two --identity arguments are required", file=sys.stderr)
        return 2

    identity_a, identity_b = identities[0], identities[1]

    try:
        config = _config_from_baseline(baseline)
    except ValueError as exc:
        print(f"error: invalid baseline options: {exc}", file=sys.stderr)
        return 4

    try:
        data = load_spec(baseline["spec"], config=config)
        spec = parse_spec(data)
    except SpecError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4

    log_writer: RequestLogWriter | None = None
    if not args.no_log:
        try:
            log_writer = RequestLogWriter(args.log)
        except OSError as exc:
            print(f"error: cannot open log file {args.log}: {exc}", file=sys.stderr)
            return 4

    all_findings: list = []
    options = baseline["options"]

    try:
        with MantisClient(config, log_writer=log_writer) as client:
            all_findings.extend(
                detect_bola(spec, client, config, identity_a, identity_b)
            )
            if options.get("sequences"):
                all_findings.extend(
                    detect_bfla(spec, client, config, identity_a, identity_b)
                )
                all_findings.extend(
                    detect_state_skip(spec, client, config, identity_a)
                )
    except EvidenceWriteError as exc:
        print(f"error: request executed but evidence not saved: {exc}", file=sys.stderr)
        return 5
    except TargetNotAllowed as exc:
        print(f"error: target not allowed: {exc}", file=sys.stderr)
        return 4
    except RateLimitExceeded as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except httpx.HTTPError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if log_writer is not None:
            log_writer.close()

    findings = tuple(all_findings)

    expected_ids = {f["id"] for f in baseline["expected_findings"]}
    actual_ids = {f.id for f in findings}

    still_present = expected_ids & actual_ids
    corrected = expected_ids - actual_ids
    new = actual_ids - expected_ids

    if args.format == "json":
        payload = {
            "baseline": str(args.baseline),
            "spec_title": baseline.get("spec_title"),
            "expected_count": len(expected_ids),
            "actual_count": len(actual_ids),
            "still_present": sorted(still_present),
            "corrected": sorted(corrected),
            "new": sorted(new),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(_format_markdown(baseline, expected_ids, actual_ids, still_present, corrected, new, findings))
    else:
        _print_human(baseline, expected_ids, actual_ids, still_present, corrected, new)

    # Exit 0 only if nothing changed
    if corrected or new:
        return 1
    return 0


def _load_baseline(path: Path) -> dict | None:
    if not path.exists():
        print(f"error: baseline not found: {path}", file=sys.stderr)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read baseline: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print("error: baseline must be a JSON object", file=sys.stderr)
        return None
    for required in ("spec", "options", "expected_findings"):
        if required not in data:
            print(f"error: baseline missing '{required}'", file=sys.stderr)
            return None
    return data


def _config_from_baseline(baseline: dict) -> MantisConfig:
    options = baseline["options"]
    kwargs = {}
    if options.get("max_requests") is not None:
        kwargs["max_requests"] = options["max_requests"]
        kwargs["requests_per_minute"] = max(20, options["max_requests"])
    if options.get("privileged_operations"):
        kwargs["privileged_operations"] = tuple(options["privileged_operations"])
    if options.get("allowed_transitions"):
        kwargs["allowed_transitions"] = tuple(options["allowed_transitions"])
    if options.get("reset_endpoint"):
        kwargs["reset_endpoint"] = options["reset_endpoint"]
    if options.get("identity_endpoints"):
        kwargs["identity_endpoints"] = tuple(options["identity_endpoints"])
    return MantisConfig(**kwargs)


def _print_human(baseline, expected_ids, actual_ids, still_present, corrected, new) -> None:
    print("MANTIS :: REGRESSION")
    print()
    print(f"Spec: {baseline['spec']}")
    print(f"Spec title: {baseline.get('spec_title', '(unknown)')}")
    print(f"Expected findings: {len(expected_ids)}")
    print(f"Actual findings: {len(actual_ids)}")
    print()

    if still_present:
        print(f"Still present ({len(still_present)}):")
        for fid in sorted(still_present):
            print(f"  [OK] {fid}")
        print()

    if corrected:
        print(f"Corrected ({len(corrected)}):")
        for fid in sorted(corrected):
            print(f"  [FIXED] {fid}  (no longer detected)")
        print()

    if new:
        print(f"New ({len(new)}):")
        for fid in sorted(new):
            print(f"  [NEW] {fid}  (not in baseline)")
        print()

    if not corrected and not new:
        print("Verdict: EXPECTED (all present, 0 new)")
    else:
        print(f"Verdict: CHANGED ({len(corrected)} corrected, {len(new)} new)")


def _format_markdown(baseline, expected_ids, actual_ids, still_present, corrected, new, findings) -> str:
    lines = []
    lines.append(f"# MANTIS Regression Report: {baseline.get('spec_title', '(unknown)')}")
    lines.append("")
    lines.append(f"**Expected findings:** {len(expected_ids)}")
    lines.append(f"**Actual findings:** {len(actual_ids)}")
    lines.append("")
    lines.append("## Still Present")
    lines.append("")
    if still_present:
        for fid in sorted(still_present):
            lines.append(f"- `{fid}`")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Corrected")
    lines.append("")
    if corrected:
        for fid in sorted(corrected):
            lines.append(f"- `{fid}`")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## New")
    lines.append("")
    if new:
        for fid in sorted(new):
            lines.append(f"- `{fid}`")
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)