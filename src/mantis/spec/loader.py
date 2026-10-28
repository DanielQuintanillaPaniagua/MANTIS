"""Load OpenAPI spec files from local disk.

Supports JSON (.json) and YAML (.yaml, .yml). Uses yaml.safe_load
exclusively. Enforces a maximum file size from MantisConfig.

This module MUST NOT:
- send HTTP requests
- resolve $ref (that is parser.py's job)
- interpret the OpenAPI structure (that is parser.py's job)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from mantis.core.config import MantisConfig
from mantis.spec.errors import SpecLoadError


SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml"}


def load_spec(path: Path | str, config: MantisConfig | None = None) -> dict[str, Any]:
    """Load an OpenAPI spec file and return its parsed dict.

    Raises SpecLoadError on:
    - file not found
    - path is not a file
    - unsupported extension
    - file exceeds max_spec_size_bytes
    - invalid JSON / YAML syntax
    - the parsed result is not a dict
    """
    if config is None:
        config = MantisConfig()

    path = Path(path)

    if not path.exists():
        raise SpecLoadError(f"File not found: {path}")

    if not path.is_file():
        raise SpecLoadError(f"Not a file: {path}")

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise SpecLoadError(
            f"Unsupported extension '{ext}'. "
            f"Supported: {sorted(SUPPORTED_EXTENSIONS)}"
        )

    size = path.stat().st_size
    if size > config.max_spec_size_bytes:
        raise SpecLoadError(
            f"File too large: {size} bytes "
            f"(max: {config.max_spec_size_bytes})"
        )

    text = _read_text(path, ext)
    data = _parse(text, ext, path)

    if not isinstance(data, dict):
        raise SpecLoadError(
            f"Spec must be a mapping at the top level, got {type(data).__name__}"
        )

    return data


def _read_text(path: Path, ext: str) -> str:
    """Read the file as UTF-8, tolerating a BOM if present.

    We do not error on BOM; some Windows editors add it silently.
    """
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            return f.read()
    except OSError as exc:
        raise SpecLoadError(f"Cannot read {path}: {exc}") from exc


def _parse(text: str, ext: str, path: Path) -> Any:
    """Parse text as JSON or YAML, based on extension."""
    if ext == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecLoadError(
                f"Invalid JSON in {path}: {exc}"
            ) from exc

    # ext in (".yaml", ".yml")
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecLoadError(
            f"Invalid YAML in {path}: {exc}"
        ) from exc