"""Health check endpoints for VaultSync Server."""

from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel, Field

from vaultsync_server.config import settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Schema for server health status."""

    status: str = Field(default="ok", description="Operational status of the service")
    version: str = Field(description="Server release version")
    environment: str = Field(description="Active operating environment")
    timestamp: str = Field(description="Current UTC timestamp in ISO 8601 format")


@router.get("/health", response_model=HealthResponse, summary="Service health status")
async def get_health() -> HealthResponse:
    """Return the health status, running version, and timestamp of the server."""
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
