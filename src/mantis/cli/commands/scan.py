"""`mantis scan <spec>` command.

Loads an OpenAPI spec, runs authorization detection against the
identities provided, and prints findings.

By default, only BOLA (MK-005) is detected.
With --sequences, BFLA and state skip (MK-006) are also detected.

Exit codes:
    0 -> no findings
    1 -> one or more findings
    2 -> argument error
    3 -> rate limit
    4 -> spec error or log error
    5 -> request executed, evidence not saved
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
        "scan",
        help="Scan an API spec for authorization issues.",
        description="Run authorization detection against a spec.",
    )
    parser.add_argument("path", type=Path, help="Path to the OpenAPI spec")
    parser.add_argument(
        "--identity",
        action="append",
        required=True,
        metavar="NAME:KEY",
        help=(
            "Identity to test. Repeatable. "
            "First identity is privileged (A), second is limited (B). "
            "Example: --identity admin:lab-admin-key --identity employee:lab-employee-key"
        ),
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL for all requests (default: http://127.0.0.1:8000).",
    )
    parser.add_argument(
        "--sequences",
        action="store_true",
        help="Also run BFLA and state skip detection (MK-006).",
    )
    parser.add_argument(
        "--privileged-operations",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help=(
            "Path substring for operations that only privileged identities "
            "should execute (e.g. 'approve'). Required for BFLA detection. "
            "Repeatable."
        ),
    )
    parser.add_argument(
        "--allowed-transition",
        action="append",
        default=[],
        metavar="FIELD:FROM->TO",
        help=(
            "Declare an allowed state transition (e.g. 'status:draft->submitted'). "
            "Repeatable."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("human", "json", "markdown"),
        default="human",
        help="Output format (default: human).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Deprecated: use --format json.",
    )
    parser.add_argument(
        "--save-baseline",
        type=Path,
        default=None,
        metavar="FILE",
        help="Save expected findings to FILE for later regression testing.",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Override MantisConfig.max_requests for this scan.",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"Evidence log path (default: {DEFAULT_LOG_PATH}).",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Do not write evidence to disk.",
    )
    parser.set_defaults(func=run)


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


def _build_config(args: argparse.Namespace) -> MantisConfig:
    kwargs = {}
    if args.max_requests is not None:
        kwargs["max_requests"] = args.max_requests
        kwargs["requests_per_minute"] = max(20, args.max_requests)
    if args.privileged_operations:
        kwargs["privileged_operations"] = tuple(args.privileged_operations)
    if args.allowed_transition:
        kwargs["allowed_transitions"] = tuple(args.allowed_transition)
    return MantisConfig(**kwargs)


def run(args: argparse.Namespace) -> int:
    """Execute `mantis scan`."""
    try:
        identities = _parse_identities(args.identity, args.base_url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if len(identities) < 2:
        print("error: at least two --identity arguments are required", file=sys.stderr)
        return 2

    identity_a, identity_b = identities[0], identities[1]

    try:
        config = _build_config(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        data = load_spec(args.path, config=config)
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

    try:
        with MantisClient(config, log_writer=log_writer) as client:
            all_findings.extend(
                detect_bola(spec, client, config, identity_a, identity_b)
            )
            if args.sequences:
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
        print("hint: use --max-requests N to raise the session limit", file=sys.stderr)
        return 3
    except httpx.HTTPError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if log_writer is not None:
            log_writer.close()

    findings = tuple(all_findings)

    # Save baseline if requested
    if args.save_baseline is not None:
        _save_baseline(
            path=args.save_baseline,
            spec_path=args.path,
            spec_title=spec.title,
            args=args,
            identities=identities,
            findings=findings,
        )

    # Determine format (--json is a deprecated alias for --format json)
    output_format = "json" if args.json else args.format

    if output_format == "json":
        print(format_findings_json(findings, spec_title=spec.title))
    elif output_format == "markdown":
        print(format_findings_markdown(findings, spec_title=spec.title))
    else:
        _print_human(findings, identity_a, identity_b, args.sequences)

    return 1 if findings else 0


def _save_baseline(
    *,
    path: Path,
    spec_path: Path,
    spec_title: str,
    args: argparse.Namespace,
    identities: list[Identity],
    findings: tuple,
) -> None:
    """Write the expected findings to a baseline JSON file for regression."""
    payload = {
        "spec": str(spec_path),
        "spec_title": spec_title,
        "options": {
            "sequences": args.sequences,
            "privileged_operations": list(args.privileged_operations),
            "allowed_transitions": list(args.allowed_transition),
            "max_requests": args.max_requests,
            "base_url": args.base_url,
        },
        "identities": [{"name": i.name} for i in identities],
        "expected_findings": [
            {"id": f.id, "type": f.type.value} for f in findings
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Baseline saved to {path}", file=sys.stderr)


def _print_human(findings, identity_a: Identity, identity_b: Identity, sequences: bool) -> None:
    print("MANTIS :: SCAN")
    print()
    print(f"Identity A: {identity_a.name}")
    print(f"Identity B: {identity_b.name}")
    if sequences:
        print("Mode: BOLA + BFLA + state skip")
    else:
        print("Mode: BOLA only (use --sequences for more)")
    print(f"Findings: {len(findings)}")
    print()
    if not findings:
        print("No findings.")
        return

    for f in findings:
        print(f"[{f.severity.value.upper()}] {f.id}")
        print(f"  Type: {f.type.value}")
        print(f"  Operation: {f.operation_method} {f.operation_path}")
        print(f"  Identity: {f.identity}")
        print(f"  Confidence: {f.confidence.value}")
        print(f"  Summary: {f.summary}")
        print(f"  Reproduction:")
        for step in f.reproduction:
            print(f"    {step}")
        print()