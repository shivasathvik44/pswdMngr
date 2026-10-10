"""Test fixtures for VaultSync Server tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from vaultsync_server.main import create_app


@pytest.fixture
def app():
    """Create a test FastAPI application instance."""
    return create_app()


@pytest.fixture
async def async_client(app) -> AsyncClient:
    """Async HTTP test client bound to the FastAPI application via ASGITransport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
