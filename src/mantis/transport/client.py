"""Controlled HTTP client for MANTIS.

This is infrastructure. It does not decide what to request, nor does
it detect anything. It sends requests, respects limits, and logs
evidence. Detection logic lives elsewhere.

Rate limits are enforced here, not at the CLI, so that future engines
(sequences, generation) inherit them for free.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from mantis.core.config import MantisConfig
from mantis.transport.log import RequestLog, RequestLogWriter, utc_now_iso


class RateLimitExceeded(Exception):
    """Raised when a MantisConfig limit would be exceeded."""


@dataclass
class _WindowCounter:
    """Tracks requests within a rolling window.

    We keep it simple: a list of timestamps. For MK-003 scale
    (tens of requests), this is fine. If we ever need thousands,
    we switch to a token bucket.
    """

    window_seconds: float
    max_in_window: int
    _timestamps: list[float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._timestamps is None:
            self._timestamps = []

    def check_and_record(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t >= cutoff]
        if len(self._timestamps) >= self.max_in_window:
            raise RateLimitExceeded(
                f"Rate limit: {self.max_in_window} requests "
                f"per {self.window_seconds}s exceeded"
            )
        self._timestamps.append(now)


class MantisClient:
    """HTTP client with rate limits, timeouts, and evidence logging."""

    def __init__(
        self,
        config: MantisConfig,
        log_writer: RequestLogWriter | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config
        self.log_writer = log_writer
        self._request_count = 0
        self.last_duration_ms: float = 0.0       
        self._minute_window = _WindowCounter(
            window_seconds=60.0,
            max_in_window=config.requests_per_minute,
        )
        self._client = httpx.Client(
            timeout=config.timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )

    def __enter__(self) -> MantisClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a single request, enforcing limits and logging evidence.

        Raises RateLimitExceeded if config limits would be exceeded.
        Raises httpx.HTTPError on network failure. In both cases,
        evidence is logged before raising.
        """
        self._check_limits()

        started = time.perf_counter()
        timestamp = utc_now_iso()
        status: int | None = None
        error: str | None = None
        response_size = 0
        response_headers: dict[str, str] = {}

        try:
            response = self._client.request(method, url, headers=headers)
            duration_ms = (time.perf_counter() - started) * 1000.0
            self.last_duration_ms = duration_ms      
            status = response.status_code
            response_size = len(response.content)
            response_headers = dict(response.headers)
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - started) * 1000.0
            error = f"{type(exc).__name__}: {exc}"
            self._record_evidence(
                timestamp=timestamp,
                method=method,
                url=url,
                status=0,
                duration_ms=duration_ms,
                request_headers=headers or {},
                response_headers={},
                response_size=0,
                error=error,
            )
            raise

        self._record_evidence(
            timestamp=timestamp,
            method=method,
            url=url,
            status=status,
            duration_ms=duration_ms,
            request_headers=headers or {},
            response_headers=response_headers,
            response_size=response_size,
            error=error,
        )
        return response

    def get(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        return self.request("GET", url, headers=headers)

    def post(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        return self.request("POST", url, headers=headers)

    def _check_limits(self) -> None:
        if self._request_count >= self.config.max_requests:
            raise RateLimitExceeded(
                f"Max requests for this session: {self.config.max_requests}"
            )
        now = time.monotonic()
        self._minute_window.check_and_record(now)
        self._request_count += 1

    def _record_evidence(
        self,
        *,
        timestamp: str,
        method: str,
        url: str,
        status: int,
        duration_ms: float,
        request_headers: dict[str, str],
        response_headers: dict[str, str],
        response_size: int,
        error: str | None,
    ) -> None:
        if self.log_writer is None:
            return
        log = RequestLog(
            timestamp=timestamp,
            method=method,
            url=url,
            status=status,
            duration_ms=duration_ms,
            request_headers=request_headers,
            response_headers=response_headers,
            response_size=response_size,
            error=error,
        )
        self.log_writer.write(log)

