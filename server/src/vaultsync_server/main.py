"""Main application entry point for VaultSync Server."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from vaultsync_server.api.auth import router as auth_router
from vaultsync_server.api.health import router as health_router
from vaultsync_server.api.records import router as records_router
from vaultsync_server.api.sessions import router as sessions_router
from vaultsync_server.api.sync import router as sync_router
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
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return response


class PayloadTooLargeError(Exception):
    """Raised when an incoming request body exceeds the configured maximum size."""


class PayloadSizeLimitMiddleware:
    """Enforce strict upper bound on incoming request body size to prevent memory exhaustion.

    Protects against:
    - Declared oversized Content-Length headers (rejected immediately on fast-path).
    - Missing or undeclared Content-Length headers.
    - Chunked transfer encoding and streamed request bodies.
    - Falsified or mismatched Content-Length headers where actual received bytes exceed the limit.
    """

    def __init__(self, app, max_bytes: int = settings.max_payload_size_bytes):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length")

        # 1. Fast-path check: Content-Length header verification
        if content_length_raw is not None:
            try:
                declared_len = int(content_length_raw.decode("ascii").strip())
                if declared_len < 0:
                    response = JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
                    await response(scope, receive, send)
                    return
                if declared_len > self.max_bytes:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": f"Payload too large. Maximum permitted size is {self.max_bytes} bytes."},
                    )
                    await response(scope, receive, send)
                    return
            except (ValueError, UnicodeDecodeError):
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
                await response(scope, receive, send)
                return

        # 2. Streaming / chunked / undeclared length body verification
        received_bytes = 0
        response_started = False

        async def custom_receive():
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received_bytes += len(body)
                if received_bytes > self.max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Payload too large. Maximum permitted size is {self.max_bytes} bytes.",
                    )
            return message

        async def custom_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, custom_receive, custom_send)
        except (HTTPException, PayloadTooLargeError) as exc:
            if not response_started:
                status_code = getattr(exc, "status_code", 413)
                detail = getattr(exc, "detail", f"Payload too large. Maximum permitted size is {self.max_bytes} bytes.")
                response = JSONResponse(
                    status_code=status_code,
                    content={"detail": detail},
                )
                await response(scope, receive, send)


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

    # Defensive middleware:
    app.add_middleware(PayloadSizeLimitMiddleware, max_bytes=settings.max_payload_size_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    # Root health endpoint
    app.include_router(health_router)

    # API v1 endpoints
    app.include_router(health_router, prefix=settings.api_v1_prefix)
    app.include_router(auth_router, prefix=settings.api_v1_prefix)
    app.include_router(sessions_router, prefix=settings.api_v1_prefix)
    app.include_router(records_router, prefix=settings.api_v1_prefix)
    app.include_router(sync_router, prefix=settings.api_v1_prefix)

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
