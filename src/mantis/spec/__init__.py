"""OpenAPI spec engine for MANTIS.

Reads local OpenAPI 3.0.x / 3.1.x documents (JSON or YAML), validates
them minimally, and produces a normalized internal model (ApiSpec)
that the rest of MANTIS can consume without re-interpreting OpenAPI.

This package MUST NOT:
- send HTTP requests
- resolve external $ref
- start the lab
"""