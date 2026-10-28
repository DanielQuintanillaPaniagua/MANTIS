"""Unit tests for the normalized spec model.

These tests do not parse anything. They verify the model's shape
and invariants (immutability, enum values, defaults).
"""

import pytest

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


def test_http_method_values():
    assert HttpMethod.GET == "GET"
    assert HttpMethod.POST == "POST"
    assert HttpMethod.PATCH == "PATCH"


def test_parameter_location_values():
    assert ParameterLocation.PATH == "path"
    assert ParameterLocation.QUERY == "query"
    assert ParameterLocation.HEADER == "header"
    assert ParameterLocation.COOKIE == "cookie"


def test_security_scheme_type_values():
    assert SecuritySchemeType.API_KEY == "apiKey"
    assert SecuritySchemeType.HTTP == "http"
    assert SecuritySchemeType.OAUTH2 == "oauth2"
    assert SecuritySchemeType.OPENID_CONNECT == "openIdConnect"


def test_parameter_is_frozen():
    p = Parameter(name="id", location=ParameterLocation.PATH, required=True)
    with pytest.raises(Exception):  # FrozenInstanceError
        p.name = "other"  # type: ignore[misc]


def test_operation_has_sensible_defaults():
    op = Operation(method=HttpMethod.GET, path="/health")
    assert op.parameters == ()
    assert op.tags == ()
    assert op.responses == ()
    assert op.security == ()
    assert op.request_body is None


def test_security_requirement_defaults_to_empty_dict():
    req = SecurityRequirement()
    assert req.schemes == {}


def test_security_requirement_preserves_and_structure():
    """One SecurityRequirement with two schemes = AND."""
    req = SecurityRequirement(schemes={"apiKey": (), "mtls": ()})
    assert set(req.schemes.keys()) == {"apiKey", "mtls"}


def test_operation_security_list_is_or():
    """Two SecurityRequirement objects in a tuple = OR."""
    req_a = SecurityRequirement(schemes={"apiKey": ()})
    req_b = SecurityRequirement(schemes={"oauth": ("read",)})
    op = Operation(method=HttpMethod.GET, path="/x", security=(req_a, req_b))
    assert len(op.security) == 2
    assert op.security[0].schemes == {"apiKey": ()}
    assert op.security[1].schemes == {"oauth": ("read",)}


def test_api_spec_minimal_construction():
    spec = ApiSpec(openapi_version="3.1.0", title="Test", version="1.0.0")
    assert spec.openapi_version == "3.1.0"
    assert spec.operations == ()
    assert spec.servers == ()
    assert spec.security_schemes == ()


def test_request_body_holds_content_types():
    rb = RequestBody(
        required=True,
        content_types=("application/json",),
    )
    assert rb.required is True
    assert rb.content_types == ("application/json",)


def test_response_holds_status_and_content_types():
    r = Response(
        status_code="200",
        description="OK",
        content_types=("application/json",),
    )
    assert r.status_code == "200"
    assert r.content_types == ("application/json",)


def test_security_scheme_api_key():
    s = SecurityScheme(
        name="ApiKey",
        type=SecuritySchemeType.API_KEY,
        api_key_name="X-API-Key",
        api_key_in="header",
    )
    assert s.type == SecuritySchemeType.API_KEY
    assert s.api_key_name == "X-API-Key"
    assert s.api_key_in == "header"


def test_security_scheme_bearer():
    s = SecurityScheme(
        name="Bearer",
        type=SecuritySchemeType.HTTP,
        http_scheme="bearer",
    )
    assert s.type == SecuritySchemeType.HTTP
    assert s.http_scheme == "bearer"