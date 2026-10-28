"""Unit tests for the spec loader."""

from pathlib import Path

import pytest

from mantis.core.config import MantisConfig
from mantis.spec.errors import SpecLoadError
from mantis.spec.loader import load_spec


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"


def test_loads_minimal_valid_json():
    data = load_spec(EXAMPLES / "minimal-valid.json")
    assert data["openapi"] == "3.0.0"
    assert "/ping" in data["paths"]


def test_loads_mantis_lab_json():
    data = load_spec(EXAMPLES / "mantis-lab.json")
    assert data["openapi"].startswith("3.")
    assert "paths" in data
    assert len(data["paths"]) >= 1


def test_loads_with_internal_refs_yaml():
    data = load_spec(EXAMPLES / "with-internal-refs.yaml")
    assert data["openapi"] == "3.0.3"
    assert "/invoices/{id}" in data["paths"]


def test_loads_invalid_missing_paths_yaml_syntactically():
    """The file is valid YAML. Missing 'paths' is parser's job, not loader's."""
    data = load_spec(EXAMPLES / "invalid-missing-paths.yaml")
    assert data["openapi"] == "3.1.0"
    assert "paths" not in data


def test_loads_invalid_external_ref_yaml_syntactically():
    """External $ref is parser's job to reject, not loader's."""
    data = load_spec(EXAMPLES / "invalid-external-ref.yaml")
    assert data["openapi"] == "3.1.0"


def test_rejects_missing_file(tmp_path: Path):
    with pytest.raises(SpecLoadError, match="File not found"):
        load_spec(tmp_path / "nope.json")


def test_rejects_directory(tmp_path: Path):
    with pytest.raises(SpecLoadError, match="Not a file"):
        load_spec(tmp_path)


def test_rejects_unsupported_extension(tmp_path: Path):
    bad = tmp_path / "spec.txt"
    bad.write_text("openapi: 3.1.0")
    with pytest.raises(SpecLoadError, match="Unsupported extension"):
        load_spec(bad)


def test_rejects_invalid_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json }")
    with pytest.raises(SpecLoadError, match="Invalid JSON"):
        load_spec(bad)


def test_rejects_invalid_yaml(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("openapi: 3.1.0\n  bad_indent: oops")
    with pytest.raises(SpecLoadError, match="Invalid YAML"):
        load_spec(bad)


def test_rejects_non_dict_top_level(tmp_path: Path):
    bad = tmp_path / "array.json"
    bad.write_text("[1, 2, 3]")
    with pytest.raises(SpecLoadError, match="must be a mapping"):
        load_spec(bad)


def test_rejects_oversized_file(tmp_path: Path):
    big = tmp_path / "big.json"
    big.write_text("{}")
    config = MantisConfig(max_spec_size_bytes=10)
    big.write_text('{"openapi": "3.1.0"}')  # longer than 10 bytes
    with pytest.raises(SpecLoadError, match="File too large"):
        load_spec(big, config=config)


def test_tolerates_utf8_bom(tmp_path: Path):
    """Files saved with UTF-8 BOM must load fine."""
    p = tmp_path / "with-bom.json"
    content = '{"openapi": "3.1.0"}'
    p.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
    data = load_spec(p)
    assert data["openapi"] == "3.1.0"