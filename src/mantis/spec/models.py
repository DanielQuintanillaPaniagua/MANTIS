"""Normalized data model for OpenAPI specs.

This module defines the objects that MANTIS uses internally after
parsing an OpenAPI document. The rest of the system (MK-005 onwards)
works with these objects, not with the raw OpenAPI dict.

All models are frozen (immutable). They are pure data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class HttpMethod(StrEnum):
    """HTTP methods supported by OpenAPI 3.x."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class ParameterLocation(StrEnum):
    """Where a parameter lives."""

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"


class SecuritySchemeType(StrEnum):
    """Types of security schemes declared by OpenAPI 3.x."""

    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"
    MUTUAL_TLS = "mutualTLS"


@dataclass(frozen=True)
class Parameter:
    """A single operation parameter."""

    name: str
    location: ParameterLocation
    required: bool
    schema_type: str | None = None
    schema_format: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class RequestBody:
    """Metadata for an operation request body."""

    required: bool
    content_types: tuple[str, ...]
    schema_ref: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class Response:
    """A declared response."""

    status_code: str
    description: str
    content_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityScheme:
    """A declared security scheme (top-level components/securitySchemes)."""

    name: str
    type: SecuritySchemeType
    # apiKey-specific
    api_key_name: str | None = None
    api_key_in: str | None = None  # "header" | "query" | "cookie"
    # http-specific
    http_scheme: str | None = None  # "basic" | "bearer" | ...
    # oauth2 / openIdConnect
    openid_connect_url: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class SecurityRequirement:
    """One alternative of security requirements.

    OpenAPI semantics:
    - A LIST of SecurityRequirement objects is OR.
    - The DICT inside ONE SecurityRequirement is AND.

    Example:
        security: [
            {"apiKey": []},              # alternative 1: apiKey alone
            {"oauth": ["read"]}          # alternative 2: oauth alone
        ]
        security: [
            {"apiKey": [], "mtls": []}   # alternative 1: apiKey AND mtls
        ]

    A named field here preserves the AND/OR structure. Do not flatten
    this to a plain list of scheme names, or MK-005 will generate
    wrong authorization hypotheses.
    """

    schemes: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Operation:
    """A single HTTP operation extracted from the spec."""

    method: HttpMethod
    path: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = ()
    parameters: tuple[Parameter, ...] = ()
    request_body: RequestBody | None = None
    responses: tuple[Response, ...] = ()
    security: tuple[SecurityRequirement, ...] = ()
    servers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApiSpec:
    """The full normalized spec.

    This is the object the rest of MANTIS consumes. It is independent
    of the original file format (JSON vs YAML).
    """

    openapi_version: str
    title: str
    version: str
    description: str | None = None
    servers: tuple[str, ...] = ()
    operations: tuple[Operation, ...] = ()
    security_schemes: tuple[SecurityScheme, ...] = ()