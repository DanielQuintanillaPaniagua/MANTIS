"""CLI entry point. Parses arguments and dispatches to commands."""

from __future__ import annotations

import argparse
import sys

from mantis.cli.commands import ping


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mantis",
        description="MANTIS — API security testing framework",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="MANTIS 0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    ping.register(subparsers)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns an exit code.

    argv=None means: use sys.argv[1:].
    Tests can pass argv=[...] to avoid touching sys.argv.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "ping":
        return ping.run(args)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())