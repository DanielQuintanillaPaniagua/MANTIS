"""Unit tests for the spec error hierarchy."""

import pytest

from mantis.spec.errors import (
    SpecError,
    SpecLoadError,
    SpecReferenceError,
    SpecValidationError,
    SpecVersionError,
)


def test_all_spec_errors_inherit_from_spec_error():
    assert issubclass(SpecLoadError, SpecError)
    assert issubclass(SpecValidationError, SpecError)
    assert issubclass(SpecVersionError, SpecError)
    assert issubclass(SpecReferenceError, SpecError)


def test_version_error_is_a_validation_error():
    assert issubclass(SpecVersionError, SpecValidationError)


def test_reference_error_is_not_a_validation_error():
    assert not issubclass(SpecReferenceError, SpecValidationError)


def test_catching_base_catches_all():
    for exc_class in (
        SpecLoadError,
        SpecValidationError,
        SpecVersionError,
        SpecReferenceError,
    ):
        with pytest.raises(SpecError):
            raise exc_class("boom")


def test_error_messages_are_preserved():
    exc = SpecVersionError("OpenAPI 2.0 is not supported")
    assert "OpenAPI 2.0" in str(exc)