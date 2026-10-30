
from dataclasses import dataclass


@dataclass(frozen=True)
class MantisConfig:
    """Basic runtime configuration for MANTIS."""

    timeout_seconds: float = 5.0
    max_requests: int = 20
    requests_per_minute: int = 20
    redacted_headers: tuple[str, ...] = (
        "authorization",
        "x-api-key",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    )
    redacted_query_params: tuple[str, ...] = (
        "api_key",
        "token",
        "access_token",
        "key",
        "secret",
        "password",
    )
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")
    allowed_ports: tuple[int, ...] = (8000,)
    max_spec_size_bytes: int = 10_000_000
    ownership_fields: tuple[str, ...] = (
        "branch_id",
        "tenant_id",
        "organization_id",
        "owner_id",
        "user_id",
    )



    def __post_init__(self) -> None:
        import math

        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite number greater than zero")

        if self.max_requests < 1:
            raise ValueError("max_requests must be at least 1")

        if self.requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1")
        if self.max_spec_size_bytes < 1:
            raise ValueError("max_spec_size_bytes must be at least 1")
        if not self.ownership_fields:
            raise ValueError("ownership_fields must not be empty")
