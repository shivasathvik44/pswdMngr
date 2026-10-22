"""Regression test suite for Phase 8.4.2 backend security remediations.

Covers:
1. SEC-01: Concurrent sync cursor allocation integrity, monotonic ordering, and pagination safety.
2. SEC-01: Transaction rollback safety (no orphaned cursor jumps or partial record commits).
3. SEC-02: Keyed synthetic salt derivation with server secret, unpredictability, and format adherence.
4. SEC-02: Production secret validation fail-closed behavior.
5. SEC-02: Real user account salt preservation and authentication compatibility.
6. SEC-03: Session last_used_at database write throttling.
7. SEC-04: OpenAPI schema and documentation endpoint disabling in production.
"""

import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
import uuid
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker

from vaultsync_server.api.auth import generate_synthetic_salt, get_synthetic_salt_key
from vaultsync_server.config import Settings, settings
from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, b64decode, b64encode
from vaultsync_server.crypto.kdf import generate_salt
from vaultsync_server.db.base import Base, create_db_engine, get_db
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.main import create_app
from vaultsync_server.services.auth import hash_password, hash_token


# ============================================================================
# Helpers
# ============================================================================

def make_dummy_envelope(record_id: str) -> str:
    """Create a minimal valid JSON envelope string for testing."""
    return EncryptedRecordEnvelope(
        version=1,
        algorithm="AES-256-GCM",
        record_id=record_id,
        nonce=b64encode(b"1" * 12),
        ciphertext=b64encode(b"test-record-ciphertext-payload-bytes"),
    ).to_json()


# ============================================================================
# SEC-01: Concurrent Sync Cursor Integrity & Pagination
# ============================================================================

def test_sec01_concurrent_sync_cursor_integrity(tmp_path: Path):
    """Verify that concurrent writes to the same account receive strictly unique, monotonic cursors."""
    db_file = tmp_path / "concurrent_cursor_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create account
    with SessionLocal() as db:
        acc = Account(
            username="cursor_user",
            account_password_hash=hash_password("Sec01Password!"),
            kdf_salt=b64encode(generate_salt()),
            sync_cursor=0,
        )
        db.add(acc)
        db.commit()
        db.refresh(acc)
        account_id = acc.id

    num_workers = 30

    def worker_task(worker_id: int) -> int:
        with SessionLocal() as db:
            now = datetime.now(timezone.utc)
            # Use atomic update returning as implemented in records.py
            cursor_stmt = (
                update(Account)
                .where(Account.id == account_id)
                .values(sync_cursor=Account.sync_cursor + 1)
                .returning(Account.sync_cursor)
            )
            new_cursor = db.execute(cursor_stmt).scalar_one()

            rec = EncryptedRecord(
                record_id=f"rec-{worker_id:03d}",
                account_id=account_id,
                ciphertext_payload=make_dummy_envelope(f"rec-{worker_id:03d}"),
                revision=1,
                sync_cursor=new_cursor,
                is_deleted=False,
                created_at=now,
                updated_at=now,
            )
            db.add(rec)
            db.commit()
            return new_cursor

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        allocated_cursors = list(executor.map(worker_task, range(num_workers)))

    # Assertions
    assert len(allocated_cursors) == num_workers, "All worker tasks must complete"
    assert len(set(allocated_cursors)) == num_workers, "All allocated cursors must be strictly unique (no duplicates)"
    assert sorted(allocated_cursors) == list(range(1, num_workers + 1)), (
        f"Cursors must be strictly contiguous from 1 to {num_workers}"
    )

    with SessionLocal() as db:
        acc = db.execute(select(Account).where(Account.id == account_id)).scalar_one()
        records = db.execute(
            select(EncryptedRecord)
            .where(EncryptedRecord.account_id == account_id)
            .order_by(EncryptedRecord.sync_cursor.asc())
        ).scalars().all()

        assert acc.sync_cursor == num_workers, f"Account sync_cursor must equal {num_workers}"
        assert len(records) == num_workers
        for i, rec in enumerate(records, start=1):
            assert rec.sync_cursor == i


@pytest.mark.anyio
async def test_sec01_sync_pagination_across_boundaries(async_client: AsyncClient, test_db_engine):
    """Verify that pagination across batches retrieves all records without skipping any due to cursor gaps."""
    # 1. Register test user
    reg_resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": "pagination_user",
            "account_password": "ValidPassword123!",
            "kdf_salt": b64encode(generate_salt()),
        },
    )
    assert reg_resp.status_code == 201

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "pagination_user", "account_password": "ValidPassword123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create 10 records sequentially
    total_records = 10
    created_record_ids = []
    for i in range(1, total_records + 1):
        rec_id = f"page-rec-{i:02d}"
        created_record_ids.append(rec_id)
        post_resp = await async_client.post(
            "/api/v1/records",
            headers=headers,
            json={
                "record_id": rec_id,
                "ciphertext_payload": make_dummy_envelope(rec_id),
            },
        )
        assert post_resp.status_code == 201
        assert post_resp.json()["sync_cursor"] == i

    # 3. Synchronize in small batches of limit=3 to test boundary advancement
    batch_size = 3
    since_cursor = 0
    synced_record_ids = []
    pages_count = 0

    while True:
        pages_count += 1
        sync_resp = await async_client.get(
            f"/api/v1/sync?since_cursor={since_cursor}&limit={batch_size}",
            headers=headers,
        )
        assert sync_resp.status_code == 200
        data = sync_resp.json()
        items = data["items"]
        synced_record_ids.extend([item["record_id"] for item in items])

        if not data["has_more"]:
            break
        assert data["next_cursor"] > since_cursor, "next_cursor must advance forward"
        since_cursor = data["next_cursor"]

    assert synced_record_ids == created_record_ids, "All records must be synced in order across page boundaries"
    assert pages_count == 4  # 3 + 3 + 3 + 1 items = 4 pages


def test_sec01_rollback_preserves_cursor_and_records(tmp_path: Path):
    """Verify that a failed write rolls back both the cursor increment and the record."""
    db_file = tmp_path / "rollback_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    with SessionLocal() as db:
        acc = Account(
            username="rollback_user",
            account_password_hash=hash_password("RollbackPassword!"),
            kdf_salt=b64encode(generate_salt()),
            sync_cursor=5,
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

    # Simulate an abort / exception during transaction
    with SessionLocal() as db:
        try:
            cursor_stmt = (
                update(Account)
                .where(Account.id == acc_id)
                .values(sync_cursor=Account.sync_cursor + 1)
                .returning(Account.sync_cursor)
            )
            new_cursor = db.execute(cursor_stmt).scalar_one()
            assert new_cursor == 6

            rec = EncryptedRecord(
                record_id="rec-aborted",
                account_id=acc_id,
                ciphertext_payload=make_dummy_envelope("rec-aborted"),
                revision=1,
                sync_cursor=new_cursor,
                is_deleted=False,
            )
            db.add(rec)
            db.flush()
            # Simulate failure before commit
            raise RuntimeError("Database error occurred before commit")
        except RuntimeError:
            db.rollback()

    with SessionLocal() as db:
        acc = db.execute(select(Account).where(Account.id == acc_id)).scalar_one()
        records = db.execute(select(EncryptedRecord).where(EncryptedRecord.account_id == acc_id)).scalars().all()
        assert acc.sync_cursor == 5, "Account sync_cursor must remain 5 after rollback"
        assert len(records) == 0, "No records should have been persisted"


# ============================================================================
# SEC-02: Keyed Synthetic Salt Derivation
# ============================================================================

def test_sec02_synthetic_salt_keyed_derivation(monkeypatch):
    """Test that synthetic salt generation is deterministic and keyed to server_secret_key."""
    username = "AliceNonExistentUser"

    # With key 1
    monkeypatch.setattr(settings, "server_secret_key", "secret-key-1-at-least-32-chars-long-alpha")
    salt1_attempt1 = generate_synthetic_salt(username)
    salt1_attempt2 = generate_synthetic_salt(username)

    # Must be deterministic for the same key and username
    assert salt1_attempt1 == salt1_attempt2

    # Salt format: 16-byte base64 string
    decoded = b64decode(salt1_attempt1, expected_length=16)
    assert len(decoded) == 16

    # With key 2
    monkeypatch.setattr(settings, "server_secret_key", "secret-key-2-at-least-32-chars-long-beta")
    salt2 = generate_synthetic_salt(username)

    # Must change when key changes
    assert salt1_attempt1 != salt2
    decoded2 = b64decode(salt2, expected_length=16)
    assert len(decoded2) == 16


def test_sec02_production_secret_validation_fail_closed():
    """Verify that Settings validation fails closed in production when server_secret_key is missing or weak."""
    # Production with default dev key must raise ValueError
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            server_secret_key="vaultsync-development-secret-key-change-in-production-min32bytes",
        )

    # Production with empty key must raise ValueError
    with pytest.raises(ValidationError):
        Settings(environment="production", server_secret_key="")

    # Production with short key must raise ValueError
    with pytest.raises(ValidationError):
        Settings(environment="production", server_secret_key="too-short")

    # Production with strong 32+ character key succeeds
    valid_settings = Settings(
        environment="production",
        server_secret_key="strong-production-server-secret-key-entropy-32chars!",
    )
    assert valid_settings.environment == "production"


@pytest.mark.anyio
async def test_sec02_real_vs_synthetic_salt(async_client: AsyncClient):
    """Verify that real account salts are preserved while non-existent accounts receive synthetic salts."""
    real_salt = b64encode(generate_salt())
    username = "existing_real_user"

    reg_resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": "AccountPassword123!",
            "kdf_salt": real_salt,
        },
    )
    assert reg_resp.status_code == 201

    # Fetch salt for existing user
    real_salt_resp = await async_client.get(f"/api/v1/auth/salt?username={username}")
    assert real_salt_resp.status_code == 200
    assert real_salt_resp.json()["kdf_salt"] == real_salt, "Real user must receive their exact stored salt"

    # Fetch salt for non-existent user
    non_existent_username = "non_existent_probe_user"
    synthetic_salt_resp = await async_client.get(f"/api/v1/auth/salt?username={non_existent_username}")
    assert synthetic_salt_resp.status_code == 200
    synthetic_salt = synthetic_salt_resp.json()["kdf_salt"]

    # Verify synthetic salt validity
    assert synthetic_salt != real_salt
    decoded = b64decode(synthetic_salt, expected_length=16)
    assert len(decoded) == 16


# ============================================================================
# SEC-03: Session last_used_at Throttling
# ============================================================================

@pytest.mark.anyio
async def test_sec03_session_last_used_throttling(async_client: AsyncClient, test_db_engine):
    """Verify that session.last_used_at writes are throttled within the configured interval."""
    # 1. Register and login
    username = "throttle_test_user"
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": "Password123!",
            "kdf_salt": b64encode(generate_salt()),
        },
    )

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": "Password123!"},
    )
    token = login_resp.json()["session_token"]
    session_uuid = uuid.UUID(login_resp.json()["session_id"])
    headers = {"Authorization": f"Bearer {token}"}

    SessionLocal = sessionmaker(bind=test_db_engine)
    with SessionLocal() as db:
        initial_session = db.execute(select(Session).where(Session.id == session_uuid)).scalar_one()
        initial_last_used = initial_session.last_used_at

    # 2. Make an immediate authenticated request (within 300s throttle window)
    resp = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert resp.status_code == 200

    with SessionLocal() as db:
        session_after_call = db.execute(select(Session).where(Session.id == session_uuid)).scalar_one()
        # Must NOT have updated last_used_at because throttle interval has not passed
        assert session_after_call.last_used_at == initial_last_used, (
            "session.last_used_at should be unchanged when called within throttle window"
        )

    # 3. Simulate passage of time by artificially setting last_used_at to 400 seconds ago
    with SessionLocal() as db:
        older_time = datetime.now(timezone.utc) - timedelta(seconds=400)
        db.execute(
            update(Session)
            .where(Session.id == session_uuid)
            .values(last_used_at=older_time)
        )
        db.commit()

    # 4. Make authenticated request after throttle window has elapsed
    resp2 = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert resp2.status_code == 200

    with SessionLocal() as db:
        updated_session = db.execute(select(Session).where(Session.id == session_uuid)).scalar_one()
        # Must have updated last_used_at to current time
        diff = (datetime.now(timezone.utc) - updated_session.last_used_at.replace(tzinfo=timezone.utc)).total_seconds()
        assert diff < 10, "session.last_used_at must be updated after throttle window passes"


# ============================================================================
# SEC-04: Disable OpenAPI / Docs Endpoints in Production
# ============================================================================

@pytest.mark.anyio
async def test_sec04_openapi_disabled_in_production(monkeypatch):
    """Verify that OpenAPI schema and interactive docs endpoints return 404 in production."""
    # Set environment to production and set a strong production key
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(
        settings,
        "server_secret_key",
        "production-secret-key-must-be-at-least-32-chars-entropy!",
    )

    prod_app = create_app()
    transport = ASGITransport(app=prod_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Docs endpoints must return 404 Not Found
        docs_resp = await client.get("/docs")
        assert docs_resp.status_code == 404, "GET /docs must return 404 in production"

        redoc_resp = await client.get("/redoc")
        assert redoc_resp.status_code == 404, "GET /redoc must return 404 in production"

        openapi_resp = await client.get("/openapi.json")
        assert openapi_resp.status_code == 404, "GET /openapi.json must return 404 in production"
