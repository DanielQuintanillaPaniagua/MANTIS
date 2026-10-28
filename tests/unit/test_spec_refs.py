"""Unit tests for $ref resolution."""

import pytest

from mantis.spec.errors import SpecReferenceError
from mantis.spec.refs import MAX_DEPTH, resolve_refs


def test_resolves_internal_ref():
    doc = {
        "components": {"schemas": {"Thing": {"type": "object"}}},
        "paths": {"/x": {"$ref": "#/components/schemas/Thing"}},
    }
    resolved = resolve_refs(doc["paths"], doc)
    assert resolved == {"/x": {"type": "object"}}


def test_resolves_nested_refs():
    doc = {
        "components": {
            "schemas": {
                "A": {"$ref": "#/components/schemas/B"},
                "B": {"type": "string"},
            }
        },
    }
    resolved = resolve_refs({"x": {"$ref": "#/components/schemas/A"}}, doc)
    assert resolved == {"x": {"type": "string"}}


def test_rejects_external_http_ref():
    doc = {}
    with pytest.raises(SpecReferenceError, match="External"):
        resolve_refs({"$ref": "https://example.com/x.json"}, doc)


def test_rejects_external_file_ref():
    doc = {}
    with pytest.raises(SpecReferenceError, match="External"):
        resolve_refs({"$ref": "./other.yaml"}, doc)


def test_rejects_unresolvable_pointer():
    doc = {"components": {"schemas": {}}}
    with pytest.raises(SpecReferenceError, match="Unresolvable"):
        resolve_refs({"$ref": "#/components/schemas/Missing"}, doc)


def test_rejects_non_string_ref():
    with pytest.raises(SpecReferenceError, match="must be a string"):
        resolve_refs({"$ref": 123}, {})


def test_rejects_circular_ref():
    doc = {
        "components": {
            "schemas": {
                "A": {"$ref": "#/components/schemas/B"},
                "B": {"$ref": "#/components/schemas/A"},
            }
        }
    }
    with pytest.raises(SpecReferenceError, match="MAX_DEPTH"):
        resolve_refs({"$ref": "#/components/schemas/A"}, doc)


def test_handles_json_pointer_escapes():
    doc = {"a/b": {"value": 1}}
    resolved = resolve_refs({"$ref": "#/a~1b"}, doc)
    assert resolved == {"value": 1}


def test_preserves_non_ref_structure():
    doc = {}
    original = {"a": 1, "b": [{"c": 2}, "d"]}
    resolved = resolve_refs(original, doc)
    assert resolved == original
    # original not mutated
    assert original == {"a": 1, "b": [{"c": 2}, "d"]}