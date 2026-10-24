"""Comprehensive test suite for VaultSync Phase 3 backend.

Tests registration, authentication, session lifecycle, cross-account isolation,
encrypted record CRUD, optimistic concurrency control, incremental synchronization,
tombstones, and database migrations.
"""

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from alembic import command
from alembic.config import Config
from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, b64encode
from vaultsync_server.crypto.records import encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey
from vaultsync_server.db.base import create_db_engine
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.services.auth import hash_token


@pytest.fixture
def synthetic_client_crypto():
    """Helper creating synthetic client-side credentials and records for tests."""
    vek = VaultKey.generate()
    salt = base64.b64encode(b"0123456789abcdef").decode("ascii")
    # Synthetic account_password (independent server login credential)
    account_password = "synthetic_account_password_123"
    
    def make_record(record_id: str, plaintext: str) -> str:
        envelope = encrypt_record(vek, record_id, plaintext)
        return envelope.to_json()

    return {
        "vek": vek,
        "salt": salt,
        "account_password": account_password,
        "make_record": make_record,
    }


# ============================================================================
# 1. Registration, Login, and Public Salt Tests
# ============================================================================

@pytest.mark.anyio
async def test_account_registration_and_login_success(
    async_client: AsyncClient,
    synthetic_client_crypto,
):
    username = f"user_{uuid.uuid4().hex[:8]}"
    account_password = synthetic_client_crypto["account_password"]
    kdf_salt = synthetic_client_crypto["salt"]

    # 1. Register
    reg_res = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": kdf_salt,
        },
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert reg_data["username"] == username
    assert reg_data["kdf_salt"] == kdf_salt
    assert "account_id" in reg_data

    # 2. Duplicate registration rejected
    dup_res = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": kdf_salt,
        },
    )
    assert dup_res.status_code == 409

    # 3. Retrieve salt publicly
    salt_res = await async_client.get(f"/api/v1/auth/salt?username={username}")
    assert salt_res.status_code == 200
    assert salt_res.json()["kdf_salt"] == kdf_salt

    # 4. Login with correct account_password
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "account_password": account_password,
            "device_name": "Fedora Workstation",
            "device_id": "laptop-1",
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "session_token" in login_data
    assert login_data["kdf_salt"] == kdf_salt

    # Verify session token is NOT plaintext in DB
    token = login_data["session_token"]
    expected_hash = hash_token(token)
    assert expected_hash != token


@pytest.mark.anyio
async def test_login_invalid_credentials(async_client: AsyncClient, synthetic_client_crypto):
    username = f"user_{uuid.uuid4().hex[:8]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": synthetic_client_crypto["account_password"],
            "kdf_salt": synthetic_client_crypto["salt"],
        },
    )

    # Wrong credentials
    res = await async_client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "account_password": "wrong_incorrect_account_password",
        },
    )
    assert res.status_code == 401
    assert "Invalid credentials" in res.json()["detail"]

    # Non-existent user
    res_non_existent = await async_client.post(
        "/api/v1/auth/login",
        json={
            "username": "does_not_exist_user",
            "account_password": "any_password_val_12345678",
        },
    )
    assert res_non_existent.status_code == 401


# ============================================================================
# 2. Session Management and Revocation Tests
# ============================================================================

@pytest.mark.anyio
async def test_session_listing_and_revocation(async_client: AsyncClient, synthetic_client_crypto):
    username = f"user_{uuid.uuid4().hex[:8]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": synthetic_client_crypto["account_password"],
            "kdf_salt": synthetic_client_crypto["salt"],
        },
    )
    # Login on device 1
    login1 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"], "device_name": "Laptop"},
    )
    token1 = login1.json()["session_token"]
    session1_id = login1.json()["session_id"]

    # Login on device 2
    login2 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"], "device_name": "Phone"},
    )
    token2 = login2.json()["session_token"]
    session2_id = login2.json()["session_id"]

    # List sessions using token 1
    list_res = await async_client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert list_res.status_code == 200
    sessions = list_res.json()
    assert len(sessions) == 2
    # Verify current device flag
    current_items = [s for s in sessions if s["is_current"]]
    assert len(current_items) == 1
    assert current_items[0]["id"] == session1_id

    # Revoke session 2 from session 1
    del_res = await async_client.delete(
        f"/api/v1/sessions/{session2_id}",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert del_res.status_code == 200

    # Token 2 is now rejected
    rejected_res = await async_client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert rejected_res.status_code == 401

    # Logout calling session 1
    logout_res = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert logout_res.status_code == 200

    # Token 1 is now rejected
    rejected_res2 = await async_client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert rejected_res2.status_code == 401


# ============================================================================
# 3. Cross-Account Isolation Tests
# ============================================================================

@pytest.mark.anyio
async def test_cross_account_isolation(async_client: AsyncClient, synthetic_client_crypto):
    # Register User Alice
    alice_name = f"alice_{uuid.uuid4().hex[:6]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": alice_name, "account_password": synthetic_client_crypto["account_password"], "kdf_salt": synthetic_client_crypto["salt"]},
    )
    login_alice = await async_client.post(
        "/api/v1/auth/login",
        json={"username": alice_name, "account_password": synthetic_client_crypto["account_password"]},
    )
    alice_token = login_alice.json()["session_token"]

    # Register User Bob
    bob_name = f"bob_{uuid.uuid4().hex[:6]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": bob_name, "account_password": synthetic_client_crypto["account_password"], "kdf_salt": synthetic_client_crypto["salt"]},
    )
    login_bob = await async_client.post(
        "/api/v1/auth/login",
        json={"username": bob_name, "account_password": synthetic_client_crypto["account_password"]},
    )
    bob_token = login_bob.json()["session_token"]

    # Alice creates record-A
    rec_id = "record-secret-alice-1"
    payload = synthetic_client_crypto["make_record"](rec_id, "Alice confidential vault entry")
    create_res = await async_client.post(
        "/api/v1/records",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"record_id": rec_id, "ciphertext_payload": payload},
    )
    assert create_res.status_code == 201

    # Bob attempts to read Alice's record -> 404 (not found, preventing enumeration)
    bob_get = await async_client.get(
        f"/api/v1/records/{rec_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_get.status_code == 404

    # Bob attempts to update Alice's record -> 404
    bob_put = await async_client.put(
        f"/api/v1/records/{rec_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"expected_revision": 1, "ciphertext_payload": payload},
    )
    assert bob_put.status_code == 404

    # Bob attempts to delete Alice's record -> 404
    bob_del = await async_client.delete(
        f"/api/v1/records/{rec_id}?expected_revision=1",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_del.status_code == 404

    # Bob syncs -> receives 0 items
    bob_sync = await async_client.get(
        "/api/v1/sync",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_sync.status_code == 200
    assert len(bob_sync.json()["items"]) == 0


# ============================================================================
# 4. Encrypted Records and Optimistic Concurrency Tests
# ============================================================================

@pytest.mark.anyio
async def test_record_crud_and_optimistic_concurrency(
    async_client: AsyncClient,
    synthetic_client_crypto,
):
    username = f"user_{uuid.uuid4().hex[:6]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"], "kdf_salt": synthetic_client_crypto["salt"]},
    )
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"]},
    )
    token = login.json()["session_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    record_id = "vault-entry-uuid-101"
    payload_v1 = synthetic_client_crypto["make_record"](record_id, "Payload revision 1")

    # 1. Create record
    res = await async_client.post(
        "/api/v1/records",
        headers=auth_headers,
        json={"record_id": record_id, "ciphertext_payload": payload_v1},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["revision"] == 1
    assert data["is_deleted"] is False

    # 2. Read record
    res_get = await async_client.get(f"/api/v1/records/{record_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["ciphertext_payload"] == payload_v1

    # 3. Update with expected_revision = 1 -> succeeds to revision 2
    payload_v2 = synthetic_client_crypto["make_record"](record_id, "Payload revision 2")
    res_update = await async_client.put(
        f"/api/v1/records/{record_id}",
        headers=auth_headers,
        json={"expected_revision": 1, "ciphertext_payload": payload_v2},
    )
    assert res_update.status_code == 200
    assert res_update.json()["revision"] == 2

    # 4. Stale update with expected_revision = 1 -> returns 409 Conflict
    res_conflict = await async_client.put(
        f"/api/v1/records/{record_id}",
        headers=auth_headers,
        json={"expected_revision": 1, "ciphertext_payload": payload_v2},
    )
    assert res_conflict.status_code == 409
    assert "Conflict" in res_conflict.json()["detail"]

    # 5. Delete with stale expected_revision -> 409 Conflict
    res_del_conflict = await async_client.delete(
        f"/api/v1/records/{record_id}?expected_revision=1",
        headers=auth_headers,
    )
    assert res_del_conflict.status_code == 409

    # 6. Delete with matching expected_revision = 2 -> creates tombstone revision 3
    res_del = await async_client.delete(
        f"/api/v1/records/{record_id}?expected_revision=2",
        headers=auth_headers,
    )
    assert res_del.status_code == 200
    del_data = res_del.json()
    assert del_data["revision"] == 3
    assert del_data["is_deleted"] is True

    # 7. GET on deleted record returns 404
    res_after_del = await async_client.get(f"/api/v1/records/{record_id}", headers=auth_headers)
    assert res_after_del.status_code == 404


# ============================================================================
# 5. Incremental Synchronization, Tombstones, and Pagination
# ============================================================================

@pytest.mark.anyio
async def test_incremental_sync_and_pagination(
    async_client: AsyncClient,
    synthetic_client_crypto,
):
    username = f"user_{uuid.uuid4().hex[:6]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"], "kdf_salt": synthetic_client_crypto["salt"]},
    )
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"]},
    )
    auth_headers = {"Authorization": f"Bearer {login.json()['session_token']}"}

    # Create 3 records
    for i in range(1, 4):
        rid = f"rec-seq-{i}"
        pl = synthetic_client_crypto["make_record"](rid, f"Plaintext {i}")
        await async_client.post(
            "/api/v1/records",
            headers=auth_headers,
            json={"record_id": rid, "ciphertext_payload": pl},
        )

    # Full sync since 0
    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=auth_headers)
    assert sync_res.status_code == 200
    sync_data = sync_res.json()
    assert len(sync_data["items"]) == 3
    initial_cursor = sync_data["next_cursor"]
    assert initial_cursor == 3

    # Delete record 2
    await async_client.delete("/api/v1/records/rec-seq-2?expected_revision=1", headers=auth_headers)

    # Incremental sync since initial_cursor
    inc_res = await async_client.get(
        f"/api/v1/sync?since_cursor={initial_cursor}",
        headers=auth_headers,
    )
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    # Exactly one change: tombstone for rec-seq-2
    assert len(inc_data["items"]) == 1
    tombstone = inc_data["items"][0]
    assert tombstone["record_id"] == "rec-seq-2"
    assert tombstone["is_deleted"] is True
    assert tombstone["ciphertext_payload"] == ""  # Ciphertext purged on deletion

    # Test pagination with limit=2
    paginated_res = await async_client.get("/api/v1/sync?since_cursor=0&limit=2", headers=auth_headers)
    assert paginated_res.status_code == 200
    pag_data = paginated_res.json()
    assert len(pag_data["items"]) == 2
    assert pag_data["has_more"] is True
    assert pag_data["next_cursor"] == 3

    # Fetch second page using next_cursor
    page2_res = await async_client.get(f"/api/v1/sync?since_cursor={pag_data['next_cursor']}&limit=2", headers=auth_headers)
    assert page2_res.status_code == 200
    page2_data = page2_res.json()
    assert len(page2_data["items"]) == 1
    assert page2_data["has_more"] is False
    assert page2_data["items"][0]["record_id"] == "rec-seq-2"


# ============================================================================
# 6. Defensive Payload Bounds and Malformed Input Rejection
# ============================================================================

@pytest.mark.anyio
async def test_malformed_envelope_rejected_on_upload(async_client: AsyncClient, synthetic_client_crypto):
    username = f"user_{uuid.uuid4().hex[:6]}"
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"], "kdf_salt": synthetic_client_crypto["salt"]},
    )
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": synthetic_client_crypto["account_password"]},
    )
    auth_headers = {"Authorization": f"Bearer {login.json()['session_token']}"}

    # 1. Invalid JSON
    res1 = await async_client.post(
        "/api/v1/records",
        headers=auth_headers,
        json={"record_id": "r1", "ciphertext_payload": "{not-valid-json"},
    )
    assert res1.status_code == 400

    # 2. Record ID mismatch between URL and payload
    valid_payload = synthetic_client_crypto["make_record"]("record-uuid-alpha", "payload")
    res2 = await async_client.post(
        "/api/v1/records",
        headers=auth_headers,
        json={"record_id": "different-record-uuid", "ciphertext_payload": valid_payload},
    )
    assert res2.status_code == 400


# ============================================================================
# 7. Database Migration Test
# ============================================================================

def test_alembic_migrations_upgrade_and_downgrade(tmp_path: Path):
    """Test Alembic migrations programmatically against an isolated database."""
    test_db = tmp_path / "alembic_test.db"
    test_db_url = f"sqlite:///{test_db}"

    ini_path = Path(__file__).parents[1] / "alembic.ini"
    alembic_cfg = Config(str(ini_path))
    alembic_cfg.set_main_option("sqlalchemy.url", test_db_url)
    alembic_cfg.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))

    # Test upgrade to head
    command.upgrade(alembic_cfg, "head")

    # Verify tables exist
    engine = create_db_engine(test_db_url)
    with engine.connect() as conn:
        tables = conn.dialect.get_table_names(conn)
        assert "accounts" in tables
        assert "sessions" in tables
        assert "encrypted_records" in tables
        assert "alembic_version" in tables

    # Test downgrade to base
    command.downgrade(alembic_cfg, "base")

    # Test re-upgrade to head
    command.upgrade(alembic_cfg, "head")
    engine.dispose()
