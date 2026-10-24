"""Automated tests for health check endpoints and server baseline."""

from datetime import datetime, timezone
import pytest
from httpx import AsyncClient


from vaultsync_server.config import settings


@pytest.mark.anyio
async def test_health_root_endpoint(async_client: AsyncClient):
    """Test GET /health returns 200 OK and valid health metadata."""
    response = await async_client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == settings.app_version
    assert "timestamp" in data
    assert "environment" in data


@pytest.mark.anyio
async def test_health_api_v1_endpoint(async_client: AsyncClient):
    """Test GET /api/v1/health returns 200 OK with identical health schema."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == settings.app_version
    
    # Verify ISO timestamp parsing
    parsed_time = datetime.fromisoformat(data["timestamp"])
    assert parsed_time.tzinfo is not None


@pytest.mark.anyio
async def test_security_headers_enforced(async_client: AsyncClient):
    """Verify defensive HTTP security headers are present on server responses."""
    response = await async_client.get("/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    assert "no-store" in headers.get("cache-control", "")
