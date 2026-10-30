"""`mantis scan <spec>` command.

Loads an OpenAPI spec, runs authorization detection against the
identities provided, and prints findings.

This is the first command that DETECTS. It uses:
- MK-004 spec parser to know the operations.
- MK-003 MantisClient to send requests.
- MK-003.1 TargetPolicy to restrict destinations.
- MK-005 analysis engine to detect BOLA.

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
from mantis.cli.commands.ping import DEFAULT_LOG_PATH
from mantis.core.config import MantisConfig
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
        "--json",
        action="store_true",
        help="Output findings as JSON.",
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
    """Parse --identity name:key pairs into Identity objects."""
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
    """Execute `mantis scan`."""
    try:
        identities = _parse_identities(args.identity, args.base_url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if len(identities) < 2:
        print(
            "error: at least two --identity arguments are required",
            file=sys.stderr,
        )
        return 2

    identity_a, identity_b = identities[0], identities[1]

    try:
        config = MantisConfig()
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

    try:
        with MantisClient(config, log_writer=log_writer) as client:
            findings = detect_bola(
                spec=spec,
                client=client,
                config=config,
                identity_a=identity_a,
                identity_b=identity_b,
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

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False, default=str))
    else:
        _print_human(findings, identity_a, identity_b)

    return 1 if findings else 0


def _print_human(findings, identity_a: Identity, identity_b: Identity) -> None:
    print("MANTIS :: SCAN")
    print()
    print(f"Identity A: {identity_a.name}")
    print(f"Identity B: {identity_b.name}")
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
        print(f"  Summary: {f.summary}")
        print(f"  Details: {f.details}")
        print(f"  Reproduction:")
        for step in f.reproduction:
            print(f"    {step}")
        print()


