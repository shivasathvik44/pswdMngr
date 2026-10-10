"""API routers package for VaultSync Server."""

from vaultsync_server.api.auth import router as auth_router
from vaultsync_server.api.health import router as health_router
from vaultsync_server.api.records import router as records_router
from vaultsync_server.api.sessions import router as sessions_router
from vaultsync_server.api.sync import router as sync_router

__all__ = [
    "health_router",
    "auth_router",
    "sessions_router",
    "records_router",
    "sync_router",
]
