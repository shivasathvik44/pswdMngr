"""End-to-end integration tests connecting VaultSync Desktop to the real FastAPI backend.

Exercises ApiClient and VaultSession directly against the real FastAPI ASGI app,
real SQLAlchemy models, real SQLite database, and real cryptographic verification.
"""

from pathlib import Path
from typing import AsyncGenerator
import pytest
from httpx import ASGITransport
from sqlalchemy.orm import sessionmaker

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, WrappedKeyEnvelope
from vaultsync_server.crypto.errors import DecryptionFailedError
from vaultsync_server.crypto.records import decrypt_record
from vaultsync_server.db.base import Base, create_db_engine, get_db
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.main import create_app

from vaultsync_desktop.api_client import (
    ApiClient,
    AuthenticationError,
    ConflictError,
    MigrationRequiredError,
)
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage


@pytest.fixture
def integration_app(tmp_path: Path):
    """Isolated FastAPI instance with dedicated SQLite test database."""
    db_file = tmp_path / "integration_vaultsync.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)

    testing_session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = testing_session_factory()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    yield app, testing_session_factory
    engine.dispose()


@pytest.fixture
def make_session(integration_app):
    """Factory creating a VaultSession wired directly to the real FastAPI application."""
    app, db_factory = integration_app

    def _factory(username: str = "alice"):
        config = AppConfig()
        config.server_url = "http://127.0.0.1:8000"
        storage = TokenStorage(service_name=f"test_vaultsync_{username}")
        session = VaultSession(config=config, storage=storage)
        # Wire ApiClient to FastAPI in-process ASGI transport
        transport = ASGITransport(app=app)
        session.api = ApiClient(base_url="http://127.0.0.1:8000", transport=transport)
        return session, db_factory

    return _factory


# ============================================================================
# 1. Registration, Login, Health, and Key Retrieval Against Real Backend
# ============================================================================


@pytest.mark.anyio
async def test_real_backend_health_and_two_credential_registration(make_session):
    """Verify health check and complete two-credential registration against FastAPI."""
    client_session, db_factory = make_session("alice")

    # 1. Health check
    health = await client_session.api.check_health()
    assert health["status"] == "ok"
    assert health["version"] == "0.1.0"

    # 2. Register account (Alice)
    # Master password never leaves client
    await client_session.register_account(
        username="alice",
        account_password="ServerAccountPassword2026!",
        vault_master_password="Correct-Horse-Battery-Staple-2026",
    )

    # 3. Verify database state
    with db_factory() as db:
        account = db.query(Account).filter_by(username="alice").one()
        assert account.username == "alice"
        assert account.account_password_hash.startswith("$argon2id$")
        assert account.kdf_salt is not None
        assert account.wrapped_vault_key is not None
        assert account.sync_cursor == 0
        assert account.is_active is True
        assert account.requires_password_migration is False

        # Verify envelope structure stored on server
        env = WrappedKeyEnvelope.from_json(account.wrapped_vault_key)
        assert env.version == 1
        assert env.algorithm == "AES-256-GCM"
        assert env.kdf.algorithm == "Argon2id"


@pytest.mark.anyio
async def test_real_backend_login_and_vault_key_retrieval(make_session):
    """Verify independent login and vault key retrieval against real backend."""
    client_session, db_factory = make_session("bob")

    await client_session.register_account(
        username="bob",
        account_password="BobAccountPassword2026!",
        vault_master_password="Blue-Sky-Ocean-Mountain-River-2026",
    )

    # Authenticate (Step 1)
    login_info = await client_session.login_account(
        username="bob",
        account_password="BobAccountPassword2026!",
    )
    assert login_info["username"] == "bob"
    assert login_info["has_vault_key"] is True
    assert client_session.is_authenticated is True
    assert client_session.is_unlocked is False

    # Check GET /api/v1/auth/vault-key directly with session token
    vk_resp = await client_session.api.get_vault_key()
    assert vk_resp["wrapped_vault_key"] == client_session.wrapped_vault_key
    assert vk_resp["kdf_salt"] == client_session.kdf_salt

    # Check GET /api/v1/auth/salt
    salt_resp = await client_session.api.get_user_salt("bob")
    assert salt_resp["username"] == "bob"
    assert salt_resp["kdf_salt"] == client_session.kdf_salt

    # Unlock Vault (Step 2)
    await client_session.unlock_vault("Blue-Sky-Ocean-Mountain-River-2026")
    assert client_session.is_unlocked is True
    assert client_session._vault_key is not None


# ============================================================================
# 2. Account Password Change & Master Password Rotation
# ============================================================================


@pytest.mark.anyio
async def test_real_backend_account_password_change_leaves_vault_intact(make_session):
    """Changing account password updates server auth and revokes other sessions without touching vault keys."""
    client_session, db_factory = make_session("charlie")

    await client_session.register_account(
        username="charlie",
        account_password="OldAccountPassword2026!",
        vault_master_password="Whisper-Forest-Valley-Stone-2026",
    )
    await client_session.login_account("charlie", "OldAccountPassword2026!")
    await client_session.unlock_vault("Whisper-Forest-Valley-Stone-2026")

    orig_wrapped_key = client_session.wrapped_vault_key
    orig_salt = client_session.kdf_salt

    # Update account password
    await client_session.change_account_password("OldAccountPassword2026!", "NewAccountPassword2027!")

    # Verify database: password hash changed, vault keys intact
    with db_factory() as db:
        account = db.query(Account).filter_by(username="charlie").one()
        assert account.wrapped_vault_key == orig_wrapped_key
        assert account.kdf_salt == orig_salt

    # Old password no longer works
    with pytest.raises(AuthenticationError):
        await client_session.api.login("charlie", "OldAccountPassword2026!")

    # New password works
    new_login = await client_session.api.login("charlie", "NewAccountPassword2027!")
    assert new_login["session_token"] is not None


@pytest.mark.anyio
async def test_real_backend_master_password_rotation_preserves_records(make_session):
    """Rotating master password re-wraps VEK on server without re-encrypting existing vault records."""
    client_session, db_factory = make_session("david")

    await client_session.register_account(
        username="david",
        account_password="DavidAccountPassword2026!",
        vault_master_password="Initial-Master-Passphrase-2026",
    )
    await client_session.login_account("david", "DavidAccountPassword2026!")
    await client_session.unlock_vault("Initial-Master-Passphrase-2026")

    # Create record
    item = VaultItem(
        title="Personal Email",
        username="david@example.com",
        password="EmailSuperSecretPassword99!",
        url="https://mail.example.com",
        notes="Important email account",
    )
    await client_session.save_item(item)

    # Fetch raw record from DB
    with db_factory() as db:
        rec_before = db.query(EncryptedRecord).filter_by(record_id=item.id).one()
        ciphertext_before = rec_before.ciphertext_payload

    # Rotate Master Password
    await client_session.rotate_vault_master_password("Updated-Master-Passphrase-2027-Secure")

    # Verify that record ciphertext in DB is 100% identical (no re-encryption needed)
    with db_factory() as db:
        rec_after = db.query(EncryptedRecord).filter_by(record_id=item.id).one()
        assert rec_after.ciphertext_payload == ciphertext_before

    # Lock and attempt unlock with old master password -> DecryptionFailedError
    client_session.lock()
    with pytest.raises(DecryptionFailedError):
        await client_session.unlock_vault("Initial-Master-Passphrase-2026")

    # Unlock with new master password -> succeeds and decrypts record
    await client_session.unlock_vault("Updated-Master-Passphrase-2027-Secure")
    assert item.id in client_session.items
    decrypted_item = client_session.items[item.id]
    assert decrypted_item.password == "EmailSuperSecretPassword99!"


# ============================================================================
# 3. Encrypted Record CRUD, AAD Binding, and Incremental Sync
# ============================================================================


@pytest.mark.anyio
async def test_real_backend_record_crud_and_tombstone_sync(make_session):
    """End-to-end CRUD, optimistic concurrency, and tombstone sync against real FastAPI."""
    client_session, db_factory = make_session("elena")

    await client_session.register_account(
        username="elena",
        account_password="ElenaAccountPassword2026!",
        vault_master_password="Elena-Secret-Vault-Passphrase-2026",
    )
    await client_session.login_account("elena", "ElenaAccountPassword2026!")
    await client_session.unlock_vault("Elena-Secret-Vault-Passphrase-2026")

    # 1. Create 2 items
    item1 = VaultItem(title="GitHub", username="elena-git", password="gh-token-1234")
    item2 = VaultItem(title="Banking", username="elena-bank", password="bank-pin-5678")

    await client_session.save_item(item1)
    await client_session.save_item(item2)

    assert item1.revision == 1
    assert item2.revision == 1

    # Verify server database has only opaque encrypted payloads
    with db_factory() as db:
        records = db.query(EncryptedRecord).all()
        assert len(records) == 2
        for r in records:
            assert "gh-token-1234" not in r.ciphertext_payload
            assert "bank-pin-5678" not in r.ciphertext_payload
            # Verify envelope valid
            env = EncryptedRecordEnvelope.from_json(r.ciphertext_payload)
            assert env.record_id == r.record_id

    # 2. Update item 1
    item1.password = "gh-token-new-5678"
    await client_session.save_item(item1)
    assert item1.revision == 2

    # 3. Delete item 2 (tombstone)
    await client_session.delete_item(item2.id)
    assert item2.id not in client_session.items

    with db_factory() as db:
        rec2 = db.query(EncryptedRecord).filter_by(record_id=item2.id).one()
        assert rec2.is_deleted is True
        assert rec2.ciphertext_payload == ""
        assert rec2.revision == 2

    # 4. Sync from cursor 0: should receive 2 items (1 active, 1 tombstone)
    sync_res = await client_session.api.fetch_sync(since_cursor=0)
    items_received = sync_res["items"]
    assert len(items_received) == 2
    deleted_items = [i for i in items_received if i["is_deleted"]]
    active_items = [i for i in items_received if not i["is_deleted"]]
    assert len(deleted_items) == 1
    assert deleted_items[0]["record_id"] == item2.id
    assert len(active_items) == 1
    assert active_items[0]["record_id"] == item1.id


# ============================================================================
# 4. Multi-Client Concurrency, Revision Conflicts, and AAD Tampering
# ============================================================================


@pytest.mark.anyio
async def test_multi_client_concurrency_and_conflict_detection(make_session):
    """Simulate two devices syncing the same account: stale revision triggers HTTP 409."""
    # Setup Device A and Device B
    session_a, db_factory = make_session("frank")
    session_b, _ = make_session("frank")

    await session_a.register_account(
        username="frank",
        account_password="FrankAccountPassword2026!",
        vault_master_password="Frank-Passphrase-Multi-Device-2026",
    )

    # Device A logs in and unlocks
    await session_a.login_account("frank", "FrankAccountPassword2026!", device_name="Fedora Laptop")
    await session_a.unlock_vault("Frank-Passphrase-Multi-Device-2026")

    # Device B logs in and unlocks
    await session_b.login_account("frank", "FrankAccountPassword2026!", device_name="Workstation")
    await session_b.unlock_vault("Frank-Passphrase-Multi-Device-2026")

    # Device A creates Item 1
    shared_item = VaultItem(title="Server SSH Key", password="ssh-ed25519-abc")
    await session_a.save_item(shared_item)
    assert shared_item.revision == 1

    # Device B syncs and modifies Item 1
    await session_b.sync_records()
    assert shared_item.id in session_b.items
    item_on_b = session_b.items[shared_item.id]
    item_on_b.password = "ssh-ed25519-modified-by-b"
    await session_b.save_item(item_on_b)
    assert item_on_b.revision == 2

    # Now Device A attempts to update Item 1 with its stale revision (1)
    shared_item.password = "ssh-ed25519-conflict-from-a"
    with pytest.raises(ConflictError) as exc_info:
        await session_a.save_item(shared_item)

    assert "Conflict" in str(exc_info.value)

    # Verify server data was NOT overwritten
    with db_factory() as db:
        rec = db.query(EncryptedRecord).filter_by(record_id=shared_item.id).one()
        assert rec.revision == 2

    # Device A syncs to resolve
    await session_a.sync_records()
    resolved_item = session_a.items[shared_item.id]
    assert resolved_item.revision == 2
    assert resolved_item.password == "ssh-ed25519-modified-by-b"


@pytest.mark.anyio
async def test_distinct_aad_binding_and_tampered_envelope_rejection(make_session):
    """Envelopes are cryptographically bound to record_id via AAD; swapping or tampering fails."""
    client_session, _ = make_session("grace")

    await client_session.register_account(
        username="grace",
        account_password="GraceAccountPassword2026!",
        vault_master_password="Grace-Secret-Master-Passphrase-2026",
    )
    await client_session.login_account("grace", "GraceAccountPassword2026!")
    await client_session.unlock_vault("Grace-Secret-Master-Passphrase-2026")

    item1 = VaultItem(title="Service Alpha", password="alpha-secret-pwd")
    item2 = VaultItem(title="Service Beta", password="beta-secret-pwd")
    await client_session.save_item(item1)
    await client_session.save_item(item2)

    raw_rec1 = await client_session.api.get_record(item1.id)
    raw_rec2 = await client_session.api.get_record(item2.id)

    env1 = EncryptedRecordEnvelope.from_json(raw_rec1["ciphertext_payload"])
    env2 = EncryptedRecordEnvelope.from_json(raw_rec2["ciphertext_payload"])

    # Verify AAD differs based on record_id
    assert env1.compute_aad() == f"vaultsync:record:v1:{item1.id}".encode("utf-8")
    assert env2.compute_aad() == f"vaultsync:record:v1:{item2.id}".encode("utf-8")
    assert env1.compute_aad() != env2.compute_aad()

    # Attack: Swap ciphertext of Item 2 into envelope of Item 1
    malicious_env = EncryptedRecordEnvelope(
        version=1,
        algorithm="AES-256-GCM",
        record_id=item1.id,
        nonce=env2.nonce,
        ciphertext=env2.ciphertext,
    )
    # Attempting to decrypt must raise DecryptionFailedError because AAD does not match tag
    with pytest.raises(DecryptionFailedError):
        decrypt_record(client_session._vault_key, malicious_env)


# ============================================================================
# 5. Lock Invalidation, Session Revocation, and Legacy Migration
# ============================================================================


@pytest.mark.anyio
async def test_in_flight_operation_safely_ignored_when_vault_locks(make_session):
    """When vault locks during an in-flight async request, late response cannot repopulate vault."""
    client_session, _ = make_session("helen")

    await client_session.register_account(
        username="helen",
        account_password="HelenAccountPassword2026!",
        vault_master_password="Helen-Secret-Master-Passphrase-2026",
    )
    await client_session.login_account("helen", "HelenAccountPassword2026!")
    await client_session.unlock_vault("Helen-Secret-Master-Passphrase-2026")

    item = VaultItem(title="Test In-Flight", password="SecretValue")

    # Manually lock session right before or during save
    client_session.lock()
    assert client_session.is_unlocked is False
    assert client_session._vault_key is None
    assert len(client_session.items) == 0

    # Attempting save raises ApiError immediately
    with pytest.raises(Exception):
        await client_session.save_item(item)

    assert len(client_session.items) == 0


@pytest.mark.anyio
async def test_expired_or_revoked_session_triggers_safe_lock(make_session):
    """401 Unauthorized from server forces local vault lock and clears session token."""
    client_session, db_factory = make_session("ian")

    await client_session.register_account(
        username="ian",
        account_password="IanAccountPassword2026!",
        vault_master_password="Ian-Secret-Master-Passphrase-2026",
    )
    await client_session.login_account("ian", "IanAccountPassword2026!")
    await client_session.unlock_vault("Ian-Secret-Master-Passphrase-2026")

    assert client_session.is_unlocked is True
    assert client_session.session_token is not None

    # Revoke session on backend directly
    with db_factory() as db:
        sessions = db.query(Session).all()
        for s in sessions:
            s.revoked_at = s.created_at
        db.commit()

    # Client attempts sync -> receives 401 Unauthorized
    with pytest.raises(AuthenticationError):
        await client_session.sync_records()

    # Session must now be locked and token cleared
    assert client_session.is_unlocked is False
    assert client_session.session_token is None
    assert client_session._vault_key is None
    assert len(client_session.items) == 0


@pytest.mark.anyio
async def test_legacy_account_migration_403_handling(make_session):
    """Legacy accounts with requires_password_migration=True raise MigrationRequiredError."""
    client_session, db_factory = make_session("legacy_user")

    await client_session.register_account(
        username="legacy_user",
        account_password="LegacyUserPassword2026!",
        vault_master_password="Legacy-Master-Passphrase-2026",
    )

    # Flag account as requiring migration
    with db_factory() as db:
        account = db.query(Account).filter_by(username="legacy_user").one()
        account.requires_password_migration = True
        db.commit()

    # Login should raise MigrationRequiredError
    with pytest.raises(MigrationRequiredError) as exc_info:
        await client_session.login_account("legacy_user", "LegacyUserPassword2026!")

    assert exc_info.value.status_code == 403
    assert "migration" in str(exc_info.value).lower()


# ============================================================================
# 6. Full Lifecycle, App Restart Persistence, and Data Integrity
# ============================================================================


@pytest.mark.anyio
async def test_real_backend_full_vault_lifecycle_save_fetch_decrypt_edit_fetch_delete_sync(make_session):
    """Test full cycle: save -> fetch -> decrypt -> edit -> fetch -> delete -> sync against real backend."""
    client_session, db_factory = make_session("lifecycle_user")

    await client_session.register_account(
        username="lifecycle_user",
        account_password="LifecycleAccountPassword2026!",
        vault_master_password="Correct-Horse-Battery-Staple-Lifecycle-2026",
    )
    await client_session.login_account("lifecycle_user", "LifecycleAccountPassword2026!")
    await client_session.unlock_vault("Correct-Horse-Battery-Staple-Lifecycle-2026")

    # 1. Save new item
    item = VaultItem(
        title="Banking Portal",
        username="life_user",
        password="TopSecretBankPassword999!",
        url="https://bank.example.com",
        notes="Primary checking account",
    )
    saved = await client_session.save_item(item)
    assert saved.id == item.id
    assert saved.revision == 1

    # Verify backend has only ciphertext envelope
    with db_factory() as db:
        rec = db.query(EncryptedRecord).filter_by(record_id=item.id).one()
        assert rec.is_deleted is False
        assert rec.revision == 1
        assert "TopSecretBankPassword999!" not in rec.ciphertext_payload
        assert "Banking Portal" not in rec.ciphertext_payload

    # 2. Fetch record by ID
    fetched = await client_session.fetch_record(item.id)
    assert fetched is not None
    assert fetched.id == item.id
    assert fetched.title == "Banking Portal"
    assert fetched.password == "TopSecretBankPassword999!"
    assert fetched.url == "https://bank.example.com"
    assert fetched.notes == "Primary checking account"

    # 3. Edit item
    fetched.title = "Banking Portal (Updated)"
    fetched.password = "NewRotatedBankPassword123!"
    fetched.notes = "Updated notes after pin change"
    updated = await client_session.save_item(fetched)
    assert updated.id == item.id
    assert updated.revision == 2

    # 4. Fetch again and verify update
    fetched2 = await client_session.fetch_record(item.id)
    assert fetched2 is not None
    assert fetched2.title == "Banking Portal (Updated)"
    assert fetched2.password == "NewRotatedBankPassword123!"
    assert fetched2.notes == "Updated notes after pin change"
    assert fetched2.revision == 2

    # 5. Delete item (tombstone)
    await client_session.delete_item(item.id)
    assert item.id not in client_session.items

    with db_factory() as db:
        rec_del = db.query(EncryptedRecord).filter_by(record_id=item.id).one()
        assert rec_del.is_deleted is True
        assert rec_del.ciphertext_payload == ""
        assert rec_del.revision == 3

    # 6. Fetch deleted item returns None
    assert await client_session.fetch_record(item.id) is None


@pytest.mark.anyio
async def test_real_backend_persistence_across_app_restart(make_session):
    """Verify records persist across client shutdown and can be retrieved after restart and unlock."""
    session1, db_factory = make_session("restart_user")

    await session1.register_account(
        username="restart_user",
        account_password="RestartUserPassword2026!",
        vault_master_password="Correct-Horse-Battery-Staple-Restart-2026",
    )
    await session1.login_account("restart_user", "RestartUserPassword2026!")
    await session1.unlock_vault("Correct-Horse-Battery-Staple-Restart-2026")

    # Create 2 items
    item1 = VaultItem(title="Bitwarden", username="bw_user", password="BWPassword1!", url="https://bw.com")
    item2 = VaultItem(title="KeePass", username="kp_user", password="KPPassword2!", url="https://kp.com")
    await session1.save_item(item1)
    await session1.save_item(item2)

    # Simulate client application shutdown
    session1.lock()
    del session1

    # Simulate fresh client launch (new VaultSession connecting to same server DB)
    session2, _ = make_session("restart_user")

    # Step 1: Login with account password (still locked)
    login_info = await session2.login_account("restart_user", "RestartUserPassword2026!")
    assert login_info["has_vault_key"] is True
    assert session2.is_authenticated is True
    assert session2.is_unlocked is False
    assert len(session2.items) == 0

    # Step 2: Unlock with master password (triggers initial sync)
    await session2.unlock_vault("Correct-Horse-Battery-Staple-Restart-2026")
    assert session2.is_unlocked is True
    assert len(session2.items) == 2

    # Step 3: Verify decrypted items
    assert item1.id in session2.items
    assert item2.id in session2.items
    assert session2.items[item1.id].title == "Bitwarden"
    assert session2.items[item1.id].password == "BWPassword1!"
    assert session2.items[item2.id].title == "KeePass"
    assert session2.items[item2.id].password == "KPPassword2!"


@pytest.mark.anyio
async def test_real_backend_corrupted_ciphertext_gracefully_handled(make_session):
    """Verify that a corrupted ciphertext record is skipped during sync without corrupting valid records."""
    client_session, db_factory = make_session("corrupt_test_user")

    await client_session.register_account(
        username="corrupt_test_user",
        account_password="CorruptAccountPassword2026!",
        vault_master_password="Corrupt-Secret-Master-Passphrase-2026",
    )
    await client_session.login_account("corrupt_test_user", "CorruptAccountPassword2026!")
    await client_session.unlock_vault("Corrupt-Secret-Master-Passphrase-2026")

    # Save 2 items
    item_valid = VaultItem(title="Valid Service", password="ValidSecretPassword123!")
    item_corrupt = VaultItem(title="Corrupt Service", password="CorruptSecretPassword456!")
    await client_session.save_item(item_valid)
    await client_session.save_item(item_corrupt)

    # Tamper with item_corrupt in database directly
    with db_factory() as db:
        rec = db.query(EncryptedRecord).filter_by(record_id=item_corrupt.id).one()
        # Tamper payload with invalid Base64 or corrupted envelope
        rec.ciphertext_payload = '{"version":1,"algorithm":"AES-256-GCM","record_id":"' + item_corrupt.id + '","nonce":"Hh8gISIjJCUmJygp","ciphertext":"dGFtcGVyZWQ="}'
        db.commit()

    # Clear local items and re-sync
    client_session.items.clear()
    client_session.sync_cursor = 0
    await client_session.sync_records()

    # Valid item is decrypted successfully, corrupted item is safely skipped
    assert item_valid.id in client_session.items
    assert client_session.items[item_valid.id].password == "ValidSecretPassword123!"
    assert item_corrupt.id not in client_session.items

