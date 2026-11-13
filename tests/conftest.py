"""Global fixtures for MANTIS tests.

This fixture starts the MANTIS lab in-memory using FastAPI's TestClient
and provides a MantisClient wired to it. No real network is used.
"""

import pytest

from fastapi.testclient import TestClient

# Importamos la app del lab
from lab.app import app as lab_app
from lab.database import get_connection, reset_db
from lab.seed import apply_seed

from mantis.core.config import MantisConfig
from mantis.transport.client import MantisClient


@pytest.fixture
def lab_client():
    """Start the lab in-memory with a seeded DB and return its TestClient."""
    conn = get_connection(":memory:")
    reset_db(conn)
    apply_seed(conn)
    conn.close()

    # Use TestClient as the transport
    with TestClient(lab_app) as client:
        yield client


@pytest.fixture
def mantis_client(lab_client):
    """Provide a MantisClient that sends requests to the TestClient.
    
    This monkeypatches httpx to route requests through the TestClient.
    """
    # Create a custom transport that delegates to the TestClient
    class TestClientTransport:
        def handle_request(self, request):
            # Convert httpx.Request to Starlette TestClient format
            response = lab_client.request(
                method=request.method,
                url=request.url.path,
                headers=dict(request.headers),
                content=request.content,
            )
            # Convert Starlette Response back to httpx.Response
            import httpx
            return httpx.Response(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.content,
            )

    # This is a simplified version. A more robust approach is to use httpx.MockTransport
    # and map URLs to the TestClient.
    
    # For MK-008.2, we'll use a simpler approach: a function that creates a MantisClient
    # with a custom transport.
    
    def _make_client(config: MantisConfig | None = None) -> MantisClient:
        if config is None:
            config = MantisConfig()
        
        # We need a real HTTP transport for the lab, but we want to use TestClient.
        # The easiest way: start a real uvicorn server on a random port.
        # But that's what we're trying to avoid.
        
        # Alternative: use httpx.MockTransport to intercept and route to TestClient.
        import httpx
        
        def handler(request: httpx.Request) -> httpx.Response:
            # Route to the TestClient
            response = lab_client.request(
                method=request.method,
                url=str(request.url),
                headers=dict(request.headers),
                content=request.content,
            )
            return httpx.Response(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.content,
            )
        
        transport = httpx.MockTransport(handler)
        
        # Pass the transport to MantisClient
        client = MantisClient(config, transport=transport)
        return client

    return _make_client