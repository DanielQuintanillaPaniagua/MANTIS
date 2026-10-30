"""`mantis spec inspect <file>` command.

Reads a local OpenAPI spec (JSON or YAML) and prints a human-readable
summary, or the full normalized model as JSON with --json.

This command DOES NOT send HTTP requests. It only parses local files.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from mantis.core.config import MantisConfig
from mantis.spec.errors import SpecError
from mantis.spec.loader import load_spec
from mantis.spec.parser import parse_spec


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `spec` subcommand and its `inspect` sub-subcommand."""
    spec_parser = subparsers.add_parser(
        "spec",
        help="Inspect local OpenAPI specifications.",
        description="Read local OpenAPI specs. No HTTP requests are sent.",
    )
    spec_sub = spec_parser.add_subparsers(dest="spec_command", metavar="SUBCOMMAND")

    inspect_parser = spec_sub.add_parser(
        "inspect",
        help="Print a summary of an OpenAPI spec.",
        description="Parse a local OpenAPI spec and print a summary.",
    )
    inspect_parser.add_argument("path", type=Path, help="Path to the spec file (.json, .yaml, .yml)")
    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the normalized model as JSON.",
    )
    inspect_parser.add_argument(
        "--security",
        action="store_true",
        help="Include security schemes in the human-readable summary.",
    )
    inspect_parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute `mantis spec inspect`."""
    if getattr(args, "spec_command", None) is None:
        print("error: missing subcommand. Try: mantis spec inspect <file>", file=sys.stderr)
        return 2

    if args.spec_command != "inspect":
        print(f"error: unknown spec subcommand: {args.spec_command}", file=sys.stderr)
        return 2

    try:
        config = MantisConfig()
        data = load_spec(args.path, config=config)
        api_spec = parse_spec(data)
    except SpecError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4

    if args.json:
        print(json.dumps(asdict(api_spec), indent=2, ensure_ascii=False, default=str))
        return 0

    _print_human_summary(api_spec, include_security=args.security)
    return 0


def _print_human_summary(api_spec, include_security: bool) -> None:
    print("MANTIS :: SPEC ENGINE")
    print()
    print(f"Document: {api_spec.title}")
    print(f"OpenAPI: {api_spec.openapi_version}")
    print(f"Operations: {len(api_spec.operations)}")
    print(f"Security schemes: {len(api_spec.security_schemes)}")
    print("Validation: PASS")
    print()
    for op in api_spec.operations:
        print(f"{op.method.value:6s} {op.path}")

    if include_security and api_spec.security_schemes:
        print()
        print("Security schemes:")
        for scheme in api_spec.security_schemes:
            line = f"  - {scheme.name} ({scheme.type.value})"
            if scheme.api_key_name:
                line += f" header={scheme.api_key_name}"
            if scheme.http_scheme:
                line += f" scheme={scheme.http_scheme}"
            print(line)

        for op in api_spec.operations:
            if op.security:
                alts = []
                for req in op.security:
                    if not req.schemes:
                        alts.append("(none)")
                    else:
                        alts.append("+".join(req.schemes.keys()))
                print(f"  {op.method.value:6s} {op.path}: {' OR '.join(alts) or '(none)'}")