"""`mantis ping <url>` command.

Sends a single GET request and reports status, duration and size.
Evidence is logged to logs/requests.jsonl.

This is the first real HTTP action from MANTIS. It does not detect
anything. It only confirms connectivity and records evidence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from mantis.core.config import MantisConfig
from mantis.transport.client import MantisClient, RateLimitExceeded
from mantis.transport.log import EvidenceWriteError, RequestLogWriter
from mantis.transport.policy import TargetNotAllowed


DEFAULT_LOG_PATH = Path("logs/requests.jsonl")


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `ping` subcommand."""
    parser = subparsers.add_parser(
        "ping",
        help="Send a single GET request and report the result.",
        description="Send a single GET request. Evidence is logged.",
    )
    parser.add_argument("url", help="Target URL (e.g. http://127.0.0.1:8000/health)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Override the default timeout (seconds).",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="K:V",
        help="Add a request header. Repeatable. Example: --header X-API-Key:abc",
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


def _parse_headers(pairs: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in pairs:
        if ":" not in pair:
            raise ValueError(f"Invalid header (expected K:V): {pair!r}")
        key, _, value = pair.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def run(args: argparse.Namespace) -> int:
    """Execute `mantis ping`."""
    try:
        headers = _parse_headers(args.header)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        config = MantisConfig(
            timeout_seconds=args.timeout if args.timeout is not None else 5.0
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    log_writer: RequestLogWriter | None = None
    if not args.no_log:
        try:
            log_writer = RequestLogWriter(args.log)
        except OSError as exc:
            print(
                f"error: cannot open log file {args.log}: {exc}",
                file=sys.stderr,
            )
            return 4

    try:
        with MantisClient(config, log_writer=log_writer) as client:
            response = client.get(args.url, headers=headers)

        size = len(response.content)
        print(f"{response.status_code} {args.url}")
        print(f"duration: {client.last_duration_ms:.1f} ms")
        print(f"size: {size} bytes")
        return 0

    except EvidenceWriteError as exc:
        print(
            f"error: request executed but evidence not saved: {exc}",
            file=sys.stderr,
        )
        return 5

    except httpx.HTTPError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    except TargetNotAllowed as exc:
        print(f"error: target not allowed: {exc}", file=sys.stderr)
        return 4

    except RateLimitExceeded as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    finally:
        if log_writer is not None:
            log_writer.close()