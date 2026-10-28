"""Resolve internal $ref pointers in an OpenAPI document.

Only internal refs (#/...) are supported. External refs (http://, https://,
file paths) are rejected with SpecReferenceError.

Recursion is bounded by MAX_DEPTH to avoid infinite loops on circular refs.
"""

from __future__ import annotations

from typing import Any

from mantis.spec.errors import SpecReferenceError


MAX_DEPTH = 32


def resolve_refs(node: Any, document: dict[str, Any], _depth: int = 0) -> Any:
    """Recursively resolve internal $ref pointers in `node`.

    Returns a new structure with all internal refs replaced by their
    target values. Does not modify the input.

    Raises SpecReferenceError on:
    - external ref
    - unresolvable pointer
    - recursion beyond MAX_DEPTH
    """
    if _depth > MAX_DEPTH:
        raise SpecReferenceError(
            f"$ref recursion exceeded MAX_DEPTH={MAX_DEPTH} (circular reference?)"
        )

    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str):
                raise SpecReferenceError(f"$ref must be a string, got {type(ref).__name__}")
            target = _resolve_pointer(ref, document)
            return resolve_refs(target, document, _depth + 1)

        return {k: resolve_refs(v, document, _depth + 1) for k, v in node.items()}

    if isinstance(node, list):
        return [resolve_refs(item, document, _depth + 1) for item in node]

    return node


def _resolve_pointer(ref: str, document: dict[str, Any]) -> Any:
    """Resolve a JSON pointer like '#/components/schemas/Invoice'."""
    if not ref.startswith("#/"):
        raise SpecReferenceError(
            f"External or invalid $ref: '{ref}'. Only internal '#/...' is allowed."
        )

    parts = ref[2:].split("/")
    current: Any = document
    for part in parts:
        # JSON Pointer escapes: ~1 -> /, ~0 -> ~
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise SpecReferenceError(f"Unresolvable $ref: '{ref}' (missing '{part}')")
        current = current[part]
    return current