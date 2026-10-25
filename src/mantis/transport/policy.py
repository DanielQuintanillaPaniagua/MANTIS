"""Target policy: which destinations MANTIS is allowed to hit.

Without this, a buggy engine could send requests to internal services
(SSRF). This is a safety layer, not a feature. It must fail closed.

Default policy: only the local lab (127.0.0.1:8000, localhost:8000, ::1:8000).
Anything else is rejected before the request is sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from mantis.core.config import MantisConfig


class TargetNotAllowed(Exception):
    """Raised when a URL is not permitted by the target policy."""


@dataclass(frozen=True)
class TargetPolicy:
    """Validates whether a URL is allowed by MantisConfig.

    Checks, in order:
    - scheme is in allowed_schemes
    - host is in allowed_hosts (case-insensitive)
    - port is in allowed_ports

    Missing port is inferred from the scheme (80 for http, 443 for https).
    Empty scheme or host is rejected.
    """

    allowed_schemes: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]

    @classmethod
    def from_config(cls, config: MantisConfig) -> TargetPolicy:
        return cls(
            allowed_schemes=config.allowed_schemes,
            allowed_hosts=config.allowed_hosts,
            allowed_ports=config.allowed_ports,
        )

    def check(self, url: str) -> None:
        """Raise TargetNotAllowed if the URL is not permitted."""
        parts = urlsplit(url)

        scheme = parts.scheme.lower()
        if not scheme or scheme not in self.allowed_schemes:
            raise TargetNotAllowed(
                f"Scheme '{scheme}' is not allowed. Allowed: {self.allowed_schemes}"
            )

        host = (parts.hostname or "").lower()
        if not host or host not in self.allowed_hosts:
            raise TargetNotAllowed(
                f"Host '{host}' is not allowed. Allowed: {self.allowed_hosts}"
            )

        port = parts.port
        if port is None:
            port = 443 if scheme == "https" else 80
        if port not in self.allowed_ports:
            raise TargetNotAllowed(
                f"Port {port} is not allowed. Allowed: {self.allowed_ports}"
            )