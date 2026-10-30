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
    RequestBody,
    Response,
    SecurityRequirement,
    SecurityScheme,
    SecuritySchemeType,
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
    security_schemes = _extract_security_schemes(data.get("components", {}))
    global_security = _extract_security_requirements(data.get("security"))
    operations = _extract_operations(data["paths"], data, global_security)

    return ApiSpec(
        openapi_version=version,
        title=title,
        version=api_version,
        description=description,
        servers=servers,
        operations=operations,
        security_schemes=security_schemes,
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
    paths: dict[str, Any],
    document: dict[str, Any],
    global_security: tuple[SecurityRequirement, ...],
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
                _build_operation(
                    path, method_enum, raw_op, path_params, global_security
                )
            )
    return tuple(operations)


def _build_operation(
    path: str,
    method: HttpMethod,
    raw: dict[str, Any],
    inherited: tuple[Parameter, ...],
    global_security: tuple[SecurityRequirement, ...],
) -> Operation:
    tags_raw = raw.get("tags", [])
    tags = (
        tuple(t for t in tags_raw if isinstance(t, str))
        if isinstance(tags_raw, list)
        else ()
    )

    op_params = _extract_parameters(raw.get("parameters", []))
    merged_params = _merge_parameters(inherited, op_params)

    request_body = _extract_request_body(raw.get("requestBody"))
    responses = _extract_responses(raw.get("responses", {}))

    # Operation-level security OVERRIDES global if key is present (even if []).
    if "security" in raw:
        op_security = _extract_security_requirements(raw["security"])
    else:
        op_security = global_security

    return Operation(
        method=method,
        path=path,
        operation_id=raw.get("operationId") if isinstance(raw.get("operationId"), str) else None,
        summary=raw.get("summary") if isinstance(raw.get("summary"), str) else None,
        description=raw.get("description") if isinstance(raw.get("description"), str) else None,
        tags=tags,
        parameters=merged_params,
        request_body=request_body,
        responses=responses,
        security=op_security,
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
def _extract_request_body(raw: Any) -> RequestBody | None:
    if not isinstance(raw, dict):
        return None

    required = bool(raw.get("required", False))
    description = raw.get("description") if isinstance(raw.get("description"), str) else None

    content = raw.get("content")
    content_types: tuple[str, ...] = ()
    schema_ref: str | None = None

    if isinstance(content, dict):
        content_types = tuple(str(k) for k in content.keys())
        # Try to capture a top-level $ref, if present, without resolving it.
        for media_type in content.values():
            if isinstance(media_type, dict):
                schema = media_type.get("schema")
                if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
                    schema_ref = schema["$ref"]
                    break

    return RequestBody(
        required=required,
        content_types=content_types,
        schema_ref=schema_ref,
        description=description,
    )


def _extract_responses(raw: Any) -> tuple[Response, ...]:
    if not isinstance(raw, dict):
        return ()

    result: list[Response] = []
    for status_code, response_raw in raw.items():
        if not isinstance(status_code, str):
            status_code = str(status_code)

        if not isinstance(response_raw, dict):
            continue

        description = response_raw.get("description")
        if not isinstance(description, str):
            description = ""

        content = response_raw.get("content")
        content_types: tuple[str, ...] = ()
        if isinstance(content, dict):
            content_types = tuple(str(k) for k in content.keys())

        result.append(
            Response(
                status_code=status_code,
                description=description,
                content_types=content_types,
            )
        )

    # Sort by status code for determinism (2xx, 4xx, 5xx, default last)
    result.sort(key=lambda r: (r.status_code == "default", r.status_code))
    return tuple(result)
def _extract_security_schemes(components: Any) -> tuple[SecurityScheme, ...]:
    if not isinstance(components, dict):
        return ()
    raw = components.get("securitySchemes")
    if not isinstance(raw, dict):
        return ()

    result: list[SecurityScheme] = []
    for name, scheme_raw in raw.items():
        if not isinstance(name, str) or not isinstance(scheme_raw, dict):
            continue

        scheme_type_raw = scheme_raw.get("type")
        try:
            scheme_type = SecuritySchemeType(scheme_type_raw)
        except (ValueError, TypeError):
            continue  # unknown type, skip

        result.append(
            SecurityScheme(
                name=name,
                type=scheme_type,
                api_key_name=scheme_raw.get("name") if isinstance(scheme_raw.get("name"), str) else None,
                api_key_in=scheme_raw.get("in") if isinstance(scheme_raw.get("in"), str) else None,
                http_scheme=scheme_raw.get("scheme") if isinstance(scheme_raw.get("scheme"), str) else None,
                openid_connect_url=scheme_raw.get("openIdConnectUrl") if isinstance(scheme_raw.get("openIdConnectUrl"), str) else None,
                description=scheme_raw.get("description") if isinstance(scheme_raw.get("description"), str) else None,
            )
        )
    return tuple(result)


def _extract_security_requirements(
    raw: Any,
) -> tuple[SecurityRequirement, ...]:
    """Parse the OpenAPI `security` list.

    - Each item in the list is one alternative (OR).
    - Each item is a dict {schemeName: [scopes]} (AND within that item).
    - An empty list means "no security requirements" (explicit opt-out).
    """
    if not isinstance(raw, list):
        return ()

    result: list[SecurityRequirement] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        schemes: dict[str, tuple[str, ...]] = {}
        for scheme_name, scopes_raw in item.items():
            if not isinstance(scheme_name, str):
                continue
            if isinstance(scopes_raw, list):
                scopes = tuple(s for s in scopes_raw if isinstance(s, str))
            else:
                scopes = ()
            schemes[scheme_name] = scopes
        result.append(SecurityRequirement(schemes=schemes))
    return tuple(result)