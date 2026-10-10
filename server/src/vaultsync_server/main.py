"""Main application entry point for VaultSync Server."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from vaultsync_server.api.health import router as health_router
from vaultsync_server.config import settings

# Configure structured logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vaultsync_server")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add defensive security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown events."""
    logger.info(
        "VaultSync Server starting up in '%s' environment (bind: %s:%d)",
        settings.environment,
        settings.host,
        settings.port,
    )
    yield
    logger.info("VaultSync Server shutting down")


def create_app() -> FastAPI:
    """Factory function to build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Self-hosted, end-to-end encrypted password manager synchronization backend.",
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Root health endpoint and versioned API health endpoint
    app.include_router(health_router)
    app.include_router(health_router, prefix=settings.api_v1_prefix)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "vaultsync_server.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
