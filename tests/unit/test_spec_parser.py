"""Unit tests for the spec parser (step 4.4.1).

Tests extraction of operations skeleton: method, path, operation_id,
summary, description, tags, servers.

Parameters inherited, security, $ref, requestBody and responses are
tested in step 4.4.2.
"""

from pathlib import Path

import pytest

from mantis.spec.errors import (
    SpecValidationError,
    SpecVersionError,
)
from mantis.spec.loader import load_spec
from mantis.spec.models import HttpMethod
from mantis.spec.parser import parse_spec
from mantis.spec.errors import SpecReferenceError
from mantis.spec.models import ParameterLocation


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"


def _load(path: Path) -> dict:
    return load_spec(EXAMPLES / path)


def test_parses_minimal_valid():
    spec = parse_spec(_load("minimal-valid.json"))
    assert spec.openapi_version == "3.0.0"
    assert spec.title == "Minimal API"
    assert spec.version == "1.0.0"
    assert len(spec.operations) == 1

    op = spec.operations[0]
    assert op.method == HttpMethod.GET
    assert op.path == "/ping"
    assert op.operation_id == "ping"
    assert op.summary == "Ping"


def test_parses_mantis_lab_operations():
    spec = parse_spec(_load("mantis-lab.json"))
    assert spec.openapi_version.startswith("3.")
    # The lab exposes 8 operations in MK-002
    assert len(spec.operations) == 8

    paths = {op.path for op in spec.operations}
    assert "/health" in paths
    assert "/invoices/{invoice_id}" in paths
    assert "/invoices/{invoice_id}/approve" in paths


def test_operations_have_correct_methods():
    spec = parse_spec(_load("mantis-lab.json"))
    methods_by_path = {
        (op.path, op.method) for op in spec.operations
    }
    assert ("/health", HttpMethod.GET) in methods_by_path
    assert ("/invoices/{invoice_id}/approve", HttpMethod.POST) in methods_by_path


def test_rejects_missing_paths():
    data = _load("invalid-missing-paths.yaml")
    with pytest.raises(SpecValidationError, match="'paths'"):
        parse_spec(data)


def test_rejects_missing_info():
    with pytest.raises(SpecValidationError, match="'info'"):
        parse_spec({"openapi": "3.1.0", "paths": {}})


def test_rejects_missing_openapi_version():
    with pytest.raises(SpecValidationError, match="'openapi'"):
        parse_spec({"info": {"title": "t", "version": "1"}, "paths": {}})


def test_rejects_unsupported_version():
    data = {
        "openapi": "2.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {},
    }
    with pytest.raises(SpecVersionError, match="Unsupported"):
        parse_spec(data)


def test_rejects_non_string_version():
    data = {"openapi": 3.1, "info": {"title": "t", "version": "1"}, "paths": {}}
    with pytest.raises(SpecVersionError, match="must be a string"):
        parse_spec(data)


def test_rejects_missing_title():
    data = {
        "openapi": "3.1.0",
        "info": {"version": "1"},
        "paths": {},
    }
    with pytest.raises(SpecValidationError, match="title"):
        parse_spec(data)


def test_rejects_missing_info_version():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t"},
        "paths": {},
    }
    with pytest.raises(SpecValidationError, match="version"):
        parse_spec(data)


def test_accepts_empty_paths():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {},
    }
    spec = parse_spec(data)
    assert spec.operations == ()


def test_extracts_tags():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "tags": ["a", "b"],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    spec = parse_spec(data)
    assert spec.operations[0].tags == ("a", "b")


def test_extracts_servers():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "servers": [
            {"url": "http://127.0.0.1:8000"},
            {"url": "https://example.com"},
        ],
        "paths": {},
    }
    spec = parse_spec(data)
    assert spec.servers == ("http://127.0.0.1:8000", "https://example.com")


def test_ignores_non_dict_path_items():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {"/x": "not a dict"},
    }
    spec = parse_spec(data)
    assert spec.operations == ()

def test_parses_internal_refs_in_parameters():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/invoices/{id}": {
                "get": {
                    "operationId": "getInvoice",
                    "parameters": [{"$ref": "#/components/parameters/InvoiceId"}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
        "components": {
            "parameters": {
                "InvoiceId": {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer"},
                }
            }
        },
    }
    spec = parse_spec(data)
    op = spec.operations[0]
    assert len(op.parameters) == 1
    assert op.parameters[0].name == "id"
    assert op.parameters[0].location == ParameterLocation.PATH
    assert op.parameters[0].required is True


def test_inherits_path_level_parameters():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/invoices/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "integer"}}
                ],
                "get": {"responses": {"200": {"description": "OK"}}},
                "post": {"responses": {"200": {"description": "OK"}}},
            }
        },
    }
    spec = parse_spec(data)
    assert len(spec.operations) == 2
    for op in spec.operations:
        assert len(op.parameters) == 1
        assert op.parameters[0].name == "id"
        assert op.parameters[0].required is True  # path params are always required


def test_operation_parameters_override_inherited():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/x/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "string"}}
                ],
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}}
                    ],
                    "responses": {"200": {"description": "OK"}},
                },
            }
        },
    }
    spec = parse_spec(data)
    op = spec.operations[0]
    assert len(op.parameters) == 1
    assert op.parameters[0].schema_type == "integer"


def test_merges_distinct_path_and_operation_parameters():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/x/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "integer"}}
                ],
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "OK"}},
                },
            }
        },
    }
    spec = parse_spec(data)
    op = spec.operations[0]
    names = {(p.name, p.location) for p in op.parameters}
    assert ("id", ParameterLocation.PATH) in names
    assert ("q", ParameterLocation.QUERY) in names


def test_rejects_external_ref_in_paths():
    data = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {"/x": {"$ref": "https://example.com/x.yaml"}},
    }
    with pytest.raises(SpecReferenceError, match="External"):
        parse_spec(data)