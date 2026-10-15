
from dataclasses import dataclass


@dataclass(frozen=True)
class MantisConfig:
    """Basic runtime configuration for MANTIS."""

    timeout_seconds: float = 5.0
    max_requests: int = 20
    requests_per_minute: int = 20

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        if self.max_requests < 1:
            raise ValueError("max_requests must be at least 1")

        if self.requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1")
