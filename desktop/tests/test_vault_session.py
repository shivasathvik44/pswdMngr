"""Automated tests for VaultSession state transitions, lock semantics, and sync."""

import time
import pytest
import httpx

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope
from vaultsync_server.crypto.errors import DecryptionFailedError
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey

from vaultsync_desktop.api_client import ConflictError
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.crypto import create_initial_vault_key_and_envelope
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage


@pytest.fixture
def mock_session_env(tmp_path):
    config = AppConfig(config_path=tmp_path / "config.json")
    storage = TokenStorage(service_name="test_vaultsync")
    session = VaultSession(config=config, storage=storage)
    return session


@pytest.mark.anyio
async def test_login_and_unlock_are_independent_operations(mock_session_env, monkeypatch):
    """Verify that server authentication and client vault unlocking are strictly independent."""
    session = mock_session_env
    master_pwd = "VaultMasterPassword2026!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/auth/login":
                return httpx.Response(
                    200,
                    json={
                        "session_token": "bearer-test-token-123",
                        "session_id": "sess-uuid-1",
                        "account_id": "acc-uuid-1",
                        "kdf_salt": salt_b64,
                        "wrapped_vault_key": wrapped_env_json,
                    },
                )
            elif path == "/api/v1/sync":
                return httpx.Response(
                    200,
                    json={"items": [], "next_cursor": 0, "server_cursor": 0, "has_more": False},
                )
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    # 1. Authenticate with account password
    await session.login_account("alice", "MyAccountPassword123!")

    # Verified property: Authenticated, but Vault is still LOCKED!
    assert session.is_authenticated is True
    assert session.session_token == "bearer-test-token-123"
    assert session.is_unlocked is False
    assert session._vault_key is None
    assert len(session.items) == 0

    # 2. Unlock with vault master password
    await session.unlock_vault(master_pwd)

    # Verified property: Now unlocked
    assert session.is_unlocked is True
    assert session._vault_key is not None
    assert session._vault_key.raw_bytes == vek.raw_bytes


@pytest.mark.anyio
async def test_wrong_vault_master_password_fails_safely(mock_session_env, monkeypatch):
    """Verify that entering an incorrect master password fails safely without

    leaving the vault unlocked or disclosing data.
    """
    session = mock_session_env
    master_pwd = "RealMasterPassword123!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "session_token": "token-1",
                    "account_id": "acc-1",
                    "kdf_salt": salt_b64,
                    "wrapped_vault_key": wrapped_env_json,
                },
            )

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")

    # Attempt unlock with wrong master password
    with pytest.raises(DecryptionFailedError):
        await session.unlock_vault("WrongCandidatePassword999!")

    # Verified safe failure properties:
    assert session.is_unlocked is False
    assert session._vault_key is None
    assert len(session.items) == 0


@pytest.mark.anyio
async def test_save_and_sync_encrypted_records(mock_session_env, monkeypatch):
    """Verify client-side encryption before upload and decryption after download."""
    session = mock_session_env
    master_pwd = "MasterPassword2026!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    server_records = {}

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            import json
            if path == "/api/v1/auth/login":
                return httpx.Response(200, json={"session_token": "t1", "kdf_salt": salt_b64, "wrapped_vault_key": wrapped_env_json})
            elif path == "/api/v1/sync":
                items = list(server_records.values())
                return httpx.Response(200, json={"items": items, "next_cursor": len(items), "server_cursor": len(items), "has_more": False})
            elif path == "/api/v1/records" and request.method == "POST":
                data = json.loads(request.content.decode("utf-8"))
                rec_id = data["record_id"]
                server_records[rec_id] = {
                    "record_id": rec_id,
                    "ciphertext_payload": data["ciphertext_payload"],
                    "revision": 1,
                    "sync_cursor": len(server_records) + 1,
                    "is_deleted": False,
                }
                return httpx.Response(201, json={"record_id": rec_id, "revision": 1})
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")
    await session.unlock_vault(master_pwd)

    # Create and save a new vault item
    item = VaultItem(title="GitHub", username="octocat", password="SuperSecretToken!", url="https://github.com")
    saved_item = await session.save_item(item)
    assert saved_item.revision == 1

    # Verify server received ONLY ciphertext envelope, never plaintext secrets
    assert len(server_records) == 1
    server_blob = server_records[item.id]["ciphertext_payload"]
    assert "SuperSecretToken!" not in server_blob
    assert "octocat" not in server_blob

    # Clear local session items and re-sync
    session.items.clear()
    session.sync_cursor = 0
    await session.sync_records()

    # Verify decrypted locally into VaultItem
    assert item.id in session.items
    synced_item = session.items[item.id]
    assert synced_item.title == "GitHub"
    assert synced_item.username == "octocat"
    assert synced_item.password == "SuperSecretToken!"


@pytest.mark.anyio
async def test_conflict_handling_raises_conflict_error(mock_session_env, monkeypatch):
    """Verify that HTTP 409 Conflict raises ConflictError without silently overwriting."""
    session = mock_session_env
    master_pwd = "MasterPassword2026!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/auth/login":
                return httpx.Response(200, json={"session_token": "t1", "kdf_salt": salt_b64, "wrapped_vault_key": wrapped_env_json})
            elif path == "/api/v1/sync":
                return httpx.Response(200, json={"items": [], "next_cursor": 0, "server_cursor": 0, "has_more": False})
            elif path.startswith("/api/v1/records/") and request.method == "PUT":
                return httpx.Response(409, json={"detail": "Conflict: expected revision 1, but current revision is 2"})
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")
    await session.unlock_vault(master_pwd)

    # Pre-populate an item
    item = VaultItem(title="Service A", revision=1)
    session.items[item.id] = item

    # Attempt save that triggers conflict
    with pytest.raises(ConflictError) as exc_info:
        await session.save_item(item)
    assert "Conflict" in str(exc_info.value)


def test_lock_clears_memory_and_triggers_callbacks(mock_session_env):
    """Verify that lock() purges VEK, clears items, and executes registered callbacks."""
    session = mock_session_env
    session.is_unlocked = True
    session._vault_key = VaultKey.generate()
    session.items["1"] = VaultItem(title="Test")

    callback_called = []
    session.add_lock_callback(lambda: callback_called.append(True))

    session.lock()

    assert session.is_unlocked is False
    assert session._vault_key is None
    assert len(session.items) == 0
    assert len(callback_called) == 1


def test_inactivity_auto_lock(mock_session_env):
    """Verify that check_inactivity() locks the vault after configured idle timeout."""
    session = mock_session_env
    session.is_unlocked = True
    session._vault_key = VaultKey.generate()
    session.config.auto_lock_minutes = 15

    # Recent activity -> no lock
    session.last_activity_time = time.time()
    assert session.check_inactivity() is False
    assert session.is_unlocked is True

    # Idle beyond 15 minutes (901 seconds) -> locks automatically!
    session.last_activity_time = time.time() - (15 * 60 + 1)
    assert session.check_inactivity() is True
    assert session.is_unlocked is False
    assert session._vault_key is None


@pytest.mark.anyio
async def test_sync_records_pagination(mock_session_env, monkeypatch):
    """Verify that sync_records loops through all available pages when has_more=True."""
    session = mock_session_env
    master_pwd = "MasterPassword2026!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    # Generate 150 encrypted items
    items_page1 = []
    for i in range(100):
        rid = f"rec-page1-{i}"
        item = VaultItem(id=rid, title=f"Title 1-{i}")
        env = encrypt_record(vek, rid, item.to_secret_json())
        items_page1.append({
            "record_id": rid,
            "ciphertext_payload": env.to_json(),
            "revision": 1,
            "sync_cursor": i + 1,
            "is_deleted": False,
        })

    items_page2 = []
    for i in range(50):
        rid = f"rec-page2-{i}"
        item = VaultItem(id=rid, title=f"Title 2-{i}")
        env = encrypt_record(vek, rid, item.to_secret_json())
        items_page2.append({
            "record_id": rid,
            "ciphertext_payload": env.to_json(),
            "revision": 1,
            "sync_cursor": 100 + i + 1,
            "is_deleted": False,
        })

    class MockPaginationTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/auth/login":
                return httpx.Response(200, json={"session_token": "t1", "kdf_salt": salt_b64, "wrapped_vault_key": wrapped_env_json})
            elif path == "/api/v1/sync":
                since_cursor = int(request.url.params.get("since_cursor", 0))
                if since_cursor < 100:
                    return httpx.Response(200, json={
                        "items": items_page1,
                        "next_cursor": 100,
                        "server_cursor": 150,
                        "has_more": True,
                    })
                else:
                    return httpx.Response(200, json={
                        "items": items_page2,
                        "next_cursor": 150,
                        "server_cursor": 150,
                        "has_more": False,
                    })
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockPaginationTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")
    await session.unlock_vault(master_pwd)

    # Sync records -> should fetch both page 1 and page 2 (total 150 items)
    await session.sync_records()
    assert len(session.items) == 150
    assert "rec-page1-0" in session.items
    assert "rec-page2-49" in session.items
    assert session.sync_cursor == 150


@pytest.mark.anyio
async def test_fetch_record_by_id(mock_session_env, monkeypatch):
    """Verify that fetch_record retrieves, decrypts, and caches an individual item by ID."""
    session = mock_session_env
    master_pwd = "MasterPassword2026!"
    vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    rec_id = "target-single-rec-id"
    item = VaultItem(id=rec_id, title="Single Item", username="admin")
    env = encrypt_record(vek, rec_id, item.to_secret_json())

    class MockSingleRecTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/auth/login":
                return httpx.Response(200, json={"session_token": "t1", "kdf_salt": salt_b64, "wrapped_vault_key": wrapped_env_json})
            elif path == "/api/v1/sync":
                return httpx.Response(200, json={"items": [], "next_cursor": 0, "server_cursor": 0, "has_more": False})
            elif path == f"/api/v1/records/{rec_id}":
                return httpx.Response(200, json={
                    "record_id": rec_id,
                    "ciphertext_payload": env.to_json(),
                    "revision": 3,
                    "sync_cursor": 1,
                    "is_deleted": False,
                })
            elif path == "/api/v1/records/missing-id":
                return httpx.Response(404, json={"detail": "Record not found"})
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockSingleRecTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")
    await session.unlock_vault(master_pwd)

    # 1. Fetch existing item
    fetched = await session.fetch_record(rec_id)
    assert fetched is not None
    assert fetched.id == rec_id
    assert fetched.title == "Single Item"
    assert fetched.username == "admin"
    assert fetched.revision == 3
    assert rec_id in session.items

    # 2. Fetch missing item -> returns None
    missing = await session.fetch_record("missing-id")
    assert missing is None


@pytest.mark.anyio
async def test_delete_item_handles_not_found(mock_session_env, monkeypatch):
    """Verify deleting a record that 404s on server removes it from session.items cleanly."""
    session = mock_session_env
    master_pwd = "MasterPassword2026!"
    _, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(
        master_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )

    class MockDeleteTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/auth/login":
                return httpx.Response(200, json={"session_token": "t1", "kdf_salt": salt_b64, "wrapped_vault_key": wrapped_env_json})
            elif path == "/api/v1/sync":
                return httpx.Response(200, json={"items": [], "next_cursor": 0, "server_cursor": 0, "has_more": False})
            elif path.startswith("/api/v1/records/") and request.method == "DELETE":
                return httpx.Response(404, json={"detail": "Record not found"})
            return httpx.Response(404)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockDeleteTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    await session.login_account("alice", "AccountPassword123!")
    await session.unlock_vault(master_pwd)

    item = VaultItem(title="To Delete")
    session.items[item.id] = item

    # Delete should succeed and remove item from session.items
    await session.delete_item(item.id)
    assert item.id not in session.items

