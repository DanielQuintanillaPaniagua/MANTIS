"""HTTP transport layer for MANTIS.

This package handles outbound HTTP requests in a controlled way:
- rate limits
- timeouts
- evidence logging

Detection logic lives elsewhere. This is infrastructure only.
"""