"""Exception hierarchy for the spec engine.

All spec-related errors inherit from SpecError, so callers can catch
the whole family with a single `except SpecError`. Specific subclasses
exist for cases where the caller wants to react differently.
"""


class SpecError(Exception):
    """Base for all spec-related errors."""


class SpecLoadError(SpecError):
    """Failed to read or parse the spec file (I/O, JSON, YAML)."""


class SpecValidationError(SpecError):
    """The document is not valid OpenAPI 3.0/3.1, or missing required fields."""


class SpecVersionError(SpecValidationError):
    """The OpenAPI version is not supported."""


class SpecReferenceError(SpecError):
    """A $ref is unresolvable or disallowed (external refs are forbidden)."""