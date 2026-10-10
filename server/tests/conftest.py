"""Test fixtures for VaultSync Server tests."""

from pathlib import Path
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import sessionmaker

from vaultsync_server.db.base import Base, create_db_engine, get_db
from vaultsync_server.main import create_app


@pytest.fixture
def test_db_engine(tmp_path: Path):
    """Create a temporary isolated SQLite database engine for testing."""
    db_file = tmp_path / "test_vaultsync.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def app(test_db_engine):
    """Create a test FastAPI application instance with overridden database session."""
    testing_session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_db_engine,
    )

    def override_get_db():
        db = testing_session_factory()
        try:
            yield db
        finally:
            db.close()

    application = create_app()
    application.dependency_overrides[get_db] = override_get_db
    yield application


@pytest.fixture
async def async_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client bound to the FastAPI application via ASGITransport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
