"""Integration tests for `mantis spec inspect`."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


EXAMPLES = Path(__file__).parent.parent.parent / "examples" / "openapi"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mantis", "spec"] + args,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_inspect_minimal_valid():
    result = _run(["inspect", str(EXAMPLES / "minimal-valid.json")])
    assert result.returncode == 0, result.stderr
    assert "MANTIS :: SPEC ENGINE" in result.stdout
    assert "Minimal API" in result.stdout
    assert "3.0.0" in result.stdout
    assert "Operations: 1" in result.stdout
    assert "GET    /ping" in result.stdout


def test_inspect_mantis_lab():
    result = _run(["inspect", str(EXAMPLES / "mantis-lab.json")])
    assert result.returncode == 0, result.stderr
    assert "MANTIS Lab" in result.stdout
    assert "Operations: 8" in result.stdout
    assert "GET    /health" in result.stdout


def test_inspect_with_security_flag():
    result = _run(["inspect", str(EXAMPLES / "with-security.yaml"), "--security"])
    assert result.returncode == 0, result.stderr
    assert "Security schemes: 3" in result.stdout
    assert "ApiKeyAuth" in result.stdout
    assert "OAuth2" in result.stdout
    assert "MTLS" in result.stdout


def test_inspect_json_output():
    result = _run(["inspect", str(EXAMPLES / "with-security.yaml"), "--json"])
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["title"] == "Secured API"
    assert data["openapi_version"] == "3.1.0"
    assert len(data["operations"]) == 3
    assert len(data["security_schemes"]) == 3


def test_inspect_json_preserves_and_or():
    result = _run(["inspect", str(EXAMPLES / "with-security.yaml"), "--json"])
    data = json.loads(result.stdout)
    admin_op = next(
        op for op in data["operations"] if op["path"] == "/admin"
    )
    # Two OR alternatives
    assert len(admin_op["security"]) == 2
    # First alternative: OAuth2 AND MTLS
    assert set(admin_op["security"][0]["schemes"].keys()) == {"OAuth2", "MTLS"}
    # Second alternative: ApiKeyAuth alone
    assert set(admin_op["security"][1]["schemes"].keys()) == {"ApiKeyAuth"}


def test_inspect_missing_file():
    result = _run(["inspect", str(EXAMPLES / "nope.json")])
    assert result.returncode == 4
    assert "SpecLoadError" in result.stderr


def test_inspect_invalid_missing_paths():
    result = _run(["inspect", str(EXAMPLES / "invalid-missing-paths.yaml")])
    assert result.returncode == 4
    assert "SpecValidationError" in result.stderr


def test_inspect_invalid_external_ref():
    result = _run(["inspect", str(EXAMPLES / "invalid-external-ref.yaml")])
    assert result.returncode == 4
    assert "SpecReferenceError" in result.stderr


def test_spec_without_subcommand():
    result = _run([])
    assert result.returncode == 2
    assert "missing subcommand" in result.stderr