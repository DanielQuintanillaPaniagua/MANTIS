"""Parse a loaded OpenAPI dict into a normalized ApiSpec.

This is step 4.4.1. It extracts the skeleton:
- openapi version, info, servers
- operations: method, path, operation_id, summary, description, tags

Parameters (inherited), security, $ref, requestBody and responses
are added in step 4.4.2.

This module MUST NOT send HTTP requests. It works on the dict
returned by loader.load_spec().
"""

from __future__ import annotations

from typing import Any

from mantis.spec.errors import SpecReferenceError, SpecValidationError, SpecVersionError
from mantis.spec.models import (
    ApiSpec,
    HttpMethod,
    Operation,
    Parameter,
    ParameterLocation,
)
from mantis.spec.refs import resolve_refs

_HTTP_METHODS = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "patch": HttpMethod.PATCH,
    "delete": HttpMethod.DELETE,
    "head": HttpMethod.HEAD,
    "options": HttpMethod.OPTIONS,
    "trace": HttpMethod.TRACE,
}


def parse_spec(data: dict[str, Any]) -> ApiSpec:
    """Parse an OpenAPI document into an ApiSpec.

    Raises SpecVersionError if the version is not 3.0.x / 3.1.x.
    Raises SpecValidationError if required fields are missing or malformed.
    """
    _validate_required_fields(data)
    version = _validate_version(data["openapi"])
    info = data["info"]

    title = _require_str(info, "title")
    api_version = _require_str(info, "version")
    description = info.get("description")

    servers = _extract_servers(data.get("servers", []))
    operations = _extract_operations(data["paths"], data)

    return ApiSpec(
        openapi_version=version,
        title=title,
        version=api_version,
        description=description,
        servers=servers,
        operations=operations,
    )


def _validate_required_fields(data: dict[str, Any]) -> None:
    for field in ("openapi", "info", "paths"):
        if field not in data:
            raise SpecValidationError(f"Missing required field: '{field}'")

    if not isinstance(data["info"], dict):
        raise SpecValidationError("'info' must be an object")

    if not isinstance(data["paths"], dict):
        raise SpecValidationError("'paths' must be an object")


def _validate_version(version: Any) -> str:
    if not isinstance(version, str):
        raise SpecVersionError(f"'openapi' must be a string, got {type(version).__name__}")

    if version.startswith("3.0.") or version.startswith("3.1."):
        return version

    raise SpecVersionError(
        f"Unsupported OpenAPI version: '{version}'. "
        f"Supported: 3.0.x, 3.1.x"
    )


def _require_str(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise SpecValidationError(f"'info.{key}' must be a non-empty string")
    return value


def _extract_servers(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    urls: list[str] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            urls.append(item["url"])
    return tuple(urls)


def _extract_operations(
    paths: dict[str, Any], document: dict[str, Any]
) -> tuple[Operation, ...]:
    operations: list[Operation] = []
    for path, path_item_raw in paths.items():
        if not isinstance(path_item_raw, dict):
            continue

        # Resolve $refs at path level so inherited parameters are concrete
        path_item = resolve_refs(path_item_raw, document)

        path_params = _extract_parameters(path_item.get("parameters", []))

        for method_lower, method_enum in _HTTP_METHODS.items():
            raw_op = path_item.get(method_lower)
            if not isinstance(raw_op, dict):
                continue
            operations.append(
                _build_operation(path, method_enum, raw_op, path_params)
            )
    return tuple(operations)


def _build_operation(
    path: str,
    method: HttpMethod,
    raw: dict[str, Any],
    inherited: tuple[Parameter, ...],
) -> Operation:
    tags_raw = raw.get("tags", [])
    tags = (
        tuple(t for t in tags_raw if isinstance(t, str))
        if isinstance(tags_raw, list)
        else ()
    )

    op_params = _extract_parameters(raw.get("parameters", []))
    merged_params = _merge_parameters(inherited, op_params)

    return Operation(
        method=method,
        path=path,
        operation_id=raw.get("operationId") if isinstance(raw.get("operationId"), str) else None,
        summary=raw.get("summary") if isinstance(raw.get("summary"), str) else None,
        description=raw.get("description") if isinstance(raw.get("description"), str) else None,
        tags=tags,
        parameters=merged_params,
    )


def _extract_parameters(raw_params: Any) -> tuple[Parameter, ...]:
    if not isinstance(raw_params, list):
        return ()
    result: list[Parameter] = []
    for raw in raw_params:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        loc = raw.get("in")
        if not isinstance(name, str) or not isinstance(loc, str):
            continue
        try:
            location = ParameterLocation(loc)
        except ValueError:
            continue  # unknown location, skip

        schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}

        result.append(
            Parameter(
                name=name,
                location=location,
                required=bool(raw.get("required", location == ParameterLocation.PATH)),
                schema_type=schema.get("type") if isinstance(schema.get("type"), str) else None,
                schema_format=schema.get("format") if isinstance(schema.get("format"), str) else None,
                description=raw.get("description") if isinstance(raw.get("description"), str) else None,
            )
        )
    return tuple(result)


def _merge_parameters(
    inherited: tuple[Parameter, ...],
    operation: tuple[Parameter, ...],
) -> tuple[Parameter, ...]:
    """Merge inherited (path-level) with operation-level params.

    Operation params override inherited ones on (name, location).
    """
    key = lambda p: (p.name, p.location)
    merged: dict[tuple[str, ParameterLocation], Parameter] = {
        key(p): p for p in inherited
    }
    for p in operation:
        merged[key(p)] = p
    return tuple(merged.values())