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