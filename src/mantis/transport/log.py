"""Evidence logging for outbound HTTP requests.

Each request/response pair becomes a single RequestLog, serialized
as one line of JSON (JSON Lines format). This makes logs easy to:

- inspect with `tail`, `grep`, `jq`
- parse incrementally (one object per line, no commas between)
- append safely (no need to rewrite the whole file)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RequestLog:
    """Immutable record of a single HTTP request/response.

    Designed to be serialized to a single JSON line.
    """

    timestamp: str
    method: str
    url: str
    status: int
    duration_ms: float
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    response_size: int = 0
    error: str | None = None

    def to_json_line(self) -> str:
        """Serialize to a single line of JSON (no trailing newline)."""
        return json.dumps(
            asdict(self),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 with 'Z' suffix.

    Example: '2026-10-19T12:00:00Z'
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RequestLogWriter:
    """Append RequestLog entries to a JSON Lines file.

    Usage:
        writer = RequestLogWriter(Path("logs/requests.jsonl"))
        writer.write(log)
        writer.close()

    Or as a context manager:
        with RequestLogWriter(Path("logs/requests.jsonl")) as writer:
            writer.write(log)
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a", encoding="utf-8")

    def write(self, log: RequestLog) -> None:
        self._file.write(log.to_json_line())
        self._file.write("\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> RequestLogWriter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()