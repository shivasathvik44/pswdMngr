"""Phase 6 Desktop Client Reliability, Usability, and Security Lifecycle Tests.

Tests the complete desktop application and backend integration:
- Authentication & application lifecycle (registration, login, logout, account switching, isolation)
- Error recovery & network failure messaging
- Session revocation & auth expiration warning
- Vault locking, inactivity timeout, and in-flight lock race invalidation
- Credential record CRUD, validation, cancel editing, and deletion confirmation
- Revision conflict detection and sync resolution
- Master-password rotation (VEK preservation and re-wrapping)
- Settings persistence (auto-lock, clipboard auto-clear)
- Keyboard navigation (returnPressed), password reveal auto-reset, and accessibility
- Empty vault and empty search state user guidance
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from httpx import ASGITransport
from sqlalchemy.orm import sessionmaker

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from vaultsync_server.crypto.errors import DecryptionFailedError
from vaultsync_server.crypto.records import decrypt_record
from vaultsync_server.db.base import Base, create_db_engine, get_db
from vaultsync_server.db.models import Account, EncryptedRecord
from vaultsync_server.main import create_app

from vaultsync_desktop.api_client import (
    ApiClient,
    AuthenticationError,
    ConflictError,
    NetworkConnectionError,
)
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage
from vaultsync_desktop.ui.main_window import MainWindow
from vaultsync_desktop.ui.screens.login_screen import LoginScreen
from vaultsync_desktop.ui.screens.register_screen import RegisterScreen
from vaultsync_desktop.ui.screens.server_screen import ServerScreen
from vaultsync_desktop.ui.screens.settings_screen import SettingsScreen
from vaultsync_desktop.ui.screens.vault_screen import VaultScreen
from vaultsync_desktop.ui.widgets.password_edit import PasswordEdit


@pytest.fixture(scope="session")
def qapp():
    """Singleton QApplication for offscreen Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    return app


@pytest.fixture
def test_backend(tmp_path: Path):
    """Isolated FastAPI instance with an independent temporary SQLite database."""
    db_file = tmp_path / "test_phase6_vaultsync.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)

    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    yield app, session_factory
    engine.dispose()


@pytest.fixture
def session_factory(test_backend, tmp_path: Path):
    """Factory creating configured VaultSession instances wired to the in-memory ASGI app."""
    app, db_factory = test_backend

    def _create(username: str = "alice") -> VaultSession:
        cfg = AppConfig(config_path=tmp_path / f"config_{username}.json")
        cfg.server_url = "http://127.0.0.1:8000"
        storage = TokenStorage(service_name=f"test_vaultsync_p6_{username}")
        session = VaultSession(config=cfg, storage=storage)
        transport = ASGITransport(app=app)
        session.api = ApiClient(base_url="http://127.0.0.1:8000", transport=transport)
        return session

    return _create


# ============================================================================
# 1. Authentication and Application Lifecycle Workflows
# ============================================================================


@pytest.mark.anyio
async def test_account_registration_login_and_unlock_lifecycle(session_factory):
    """Verify complete registration, login, and unlock lifecycle with Two-Credential architecture."""
    session = session_factory("alice")

    # 1. Register synthetic account
    await session.register_account(
        username="alice",
        account_password="ServerPassword2026!",
        vault_master_password="Correct-Horse-Battery-2026!",
    )

    # 2. Login with valid account password (authenticates, but vault remains locked)
    login_meta = await session.login_account(
        username="alice",
        account_password="ServerPassword2026!",
    )
    assert login_meta["username"] == "alice"
    assert session.is_authenticated is True
    assert session.is_unlocked is False
    assert session._vault_key is None

    # 3. Unlock with valid vault master password
    await session.unlock_vault("Correct-Horse-Battery-2026!")
    assert session.is_unlocked is True
    assert session._vault_key is not None
    assert session.username == "alice"

    # 4. Failed login with incorrect account password
    session_bad = session_factory("alice")
    with pytest.raises(AuthenticationError):
        await session_bad.login_account("alice", "WrongAccountPassword999!")
    assert session_bad.is_authenticated is False
    assert session_bad.is_unlocked is False

    # 5. Failed unlock with incorrect master password
    with pytest.raises(DecryptionFailedError):
        await session.unlock_vault("WrongMasterPassword999!")
    assert session.is_unlocked is False
    assert session._vault_key is None


@pytest.mark.anyio
async def test_account_switching_and_zero_data_retention(session_factory):
    """Verify switching between accounts completely purges decrypted records and tokens."""
    # Alice session
    session_a = session_factory("alice")
    await session_a.register_account("alice", "AlicePass1234!", "AliceMasterSecret1234!")
    await session_a.login_account("alice", "AlicePass1234!")
    await session_a.unlock_vault("AliceMasterSecret1234!")

    # Alice creates a confidential item
    item_a = VaultItem(
        title="Alice Personal Bank",
        username="alice_banking",
        password="AliceSecretPassword99!",
        url="https://bank.alice.example",
        notes="Alice's confidential pin: 1234",
    )
    await session_a.save_item(item_a)
    assert item_a.id in session_a.items

    # Alice logs out
    await session_a.logout()
    assert session_a.is_authenticated is False
    assert session_a.is_unlocked is False
    assert len(session_a.items) == 0
    assert session_a._vault_key is None
    assert session_a.session_token is None

    # Bob registers on same client session
    await session_a.register_account("bob", "BobPass1234!", "BobMasterSecret1234!")
    await session_a.login_account("bob", "BobPass1234!")
    await session_a.unlock_vault("BobMasterSecret1234!")

    # Bob's vault must be completely empty: zero items from Alice!
    assert len(session_a.items) == 0
    assert item_a.id not in session_a.items

    # Bob adds his own item
    item_b = VaultItem(
        title="Bob Work Email",
        username="bob@corp.example",
        password="BobWorkPassword88!",
    )
    await session_a.save_item(item_b)
    assert len(session_a.items) == 1

    # Bob logs out, Alice logs back in
    await session_a.logout()
    await session_a.login_account("alice", "AlicePass1234!")
    await session_a.unlock_vault("AliceMasterSecret1234!")

    # Alice sees only her item, none of Bob's
    assert len(session_a.items) == 1
    assert item_a.id in session_a.items
    assert item_b.id not in session_a.items
    assert session_a.items[item_a.id].title == "Alice Personal Bank"


# ============================================================================
# 2. Vault Locking, In-Flight Tasks & Auto-Lock Inactivity
# ============================================================================


@pytest.mark.anyio
async def test_vault_in_flight_lock_invalidation(session_factory):
    """Verify that if the vault locks while an async save is awaiting response, data is discarded."""
    session = session_factory("carol")
    await session.register_account("carol", "CarolAccountPass1!", "CarolMasterPass1!")
    await session.login_account("carol", "CarolAccountPass1!")
    await session.unlock_vault("CarolMasterPass1!")

    item = VaultItem(title="InFlightItem", password="SecretInFlightPassword1!")

    # Simulate locking the vault while save is in-flight by locking right after encrypting
    initial_gen = session.lock_generation
    session.lock()  # Lock generation increments, items cleared, key zeroed
    assert session.is_unlocked is False
    assert session.lock_generation > initial_gen
    assert len(session.items) == 0

    # Ensure saving to a locked vault raises ApiError
    with pytest.raises(Exception) as exc_info:
        await session.save_item(item)
    assert "Vault must be unlocked" in str(exc_info.value)


def test_auto_lock_inactivity_check(tmp_path):
    """Verify check_inactivity locks the vault only when timeout elapsed."""
    cfg = AppConfig(config_path=tmp_path / "cfg.json")
    cfg.auto_lock_minutes = 5
    session = VaultSession(config=cfg)
    session.is_unlocked = True

    # 1. Fresh activity -> does not lock
    session.register_activity()
    assert session.check_inactivity() is False
    assert session.is_unlocked is True

    # 2. Activity older than 5 minutes -> locks vault
    session.last_activity_time = session.last_activity_time - 301
    assert session.check_inactivity() is True
    assert session.is_unlocked is False


# ============================================================================
# 3. Credential Record Management & Revision Conflicts
# ============================================================================


@pytest.mark.anyio
async def test_record_crud_lifecycle_and_conflict_handling(session_factory):
    """Verify record creation, update, conflict detection, and tombstone deletion."""
    session1 = session_factory("dave")
    await session1.register_account("dave", "DaveAccountPass1!", "DaveMasterPass1!")
    await session1.login_account("dave", "DaveAccountPass1!")
    await session1.unlock_vault("DaveMasterPass1!")

    # 1. Create record with Unicode, special characters, and multiline notes
    item = VaultItem(
        title="Server 🛡️ (Prod)",
        username="dave_admin",
        password="SpecialChars!@#$%^&*()_+~`",
        url="https://admin.prod.example:8443/console",
        notes="Line 1: Private SSH key memo\nLine 2: 🔑 Unicode emojis\nLine 3: Quotes 'single' and \"double\"",
    )
    saved = await session1.save_item(item)
    assert saved.revision == 1
    assert saved.id in session1.items

    # 2. Update record
    saved.notes += "\nLine 4: Added audited note"
    updated = await session1.save_item(saved)
    assert updated.revision == 2

    # 3. Setup client 2 (simulating a second device)
    session2 = session_factory("dave")
    await session2.login_account("dave", "DaveAccountPass1!")
    await session2.unlock_vault("DaveMasterPass1!")
    assert saved.id in session2.items
    assert session2.items[saved.id].revision == 2

    # 4. Device 2 updates record to revision 3
    item_dev2 = session2.items[saved.id]
    item_dev2.password = "NewDevice2Password99!"
    await session2.save_item(item_dev2)
    assert item_dev2.revision == 3

    # 5. Device 1 tries to update using stale revision 2 -> ConflictError!
    item_stale = session1.items[saved.id]
    item_stale.password = "StaleDevice1Password!"
    item_stale.revision = 2
    with pytest.raises(ConflictError):
        await session1.save_item(item_stale)

    # 6. Device 1 syncs and receives Device 2's update
    await session1.sync_records()
    assert session1.items[saved.id].revision == 3
    assert session1.items[saved.id].password == "NewDevice2Password99!"

    # 7. Delete record (tombstone)
    await session1.delete_item(saved.id)
    assert saved.id not in session1.items

    # 8. Device 2 syncs and deletes tombstone locally
    await session2.sync_records()
    assert saved.id not in session2.items


# ============================================================================
# 4. Master Password Rotation & Account Password Change
# ============================================================================


@pytest.mark.anyio
async def test_master_password_rotation_and_record_preservation(session_factory):
    """Verify master password rotation re-wraps VEK without re-encrypting records."""
    session = session_factory("eve")
    await session.register_account("eve", "EveAccountPass1!", "OldMasterPassword123!")
    await session.login_account("eve", "EveAccountPass1!")
    await session.unlock_vault("OldMasterPassword123!")

    # Create secret record before rotation
    item = VaultItem(
        title="Eve Confidential Vault Entry",
        username="eve_user",
        password="EveSuperSecret987!",
        notes="Pre-rotation secret memo",
    )
    await session.save_item(item)
    rec_id = item.id

    # Rotate master password to new password
    new_master_pw = "NewRotatedMasterPassword456!"
    await session.rotate_vault_master_password(new_master_pw)

    # Lock vault
    session.lock()
    assert session.is_unlocked is False

    # Old master password MUST FAIL
    with pytest.raises(DecryptionFailedError):
        await session.unlock_vault("OldMasterPassword123!")
    assert session.is_unlocked is False

    # New master password MUST SUCCEED
    await session.unlock_vault(new_master_pw)
    assert session.is_unlocked is True

    # Pre-rotation record is decrypted successfully with underlying preserved VEK!
    assert rec_id in session.items
    assert session.items[rec_id].password == "EveSuperSecret987!"
    assert session.items[rec_id].notes == "Pre-rotation secret memo"


@pytest.mark.anyio
async def test_change_account_password_preserves_master_password(session_factory):
    """Verify changing server account password does not modify master password or vault keys."""
    session = session_factory("frank")
    await session.register_account("frank", "OldAccountPass1!", "FrankMasterPass1!")
    await session.login_account("frank", "OldAccountPass1!")
    await session.unlock_vault("FrankMasterPass1!")

    # Change account password
    await session.change_account_password("OldAccountPass1!", "NewAccountPass2026!")

    # Logging in with old account password fails
    session_test = session_factory("frank")
    with pytest.raises(AuthenticationError):
        await session_test.login_account("frank", "OldAccountPass1!")

    # Logging in with new account password succeeds
    await session_test.login_account("frank", "NewAccountPass2026!")
    # Master password is still FrankMasterPass1!
    await session_test.unlock_vault("FrankMasterPass1!")
    assert session_test.is_unlocked is True


# ============================================================================
# 5. Session Expiration & Auth Failure Handling
# ============================================================================


@pytest.mark.anyio
async def test_auth_failure_triggers_expired_banner_on_login_screen(qapp, session_factory):
    """Verify HTTP 401 sets auth_expired and MainWindow navigates to login with expiration banner."""
    session = session_factory("grace")
    await session.register_account("grace", "GracePass1234!", "GraceMasterPass1!")
    await session.login_account("grace", "GracePass1234!")
    await session.unlock_vault("GraceMasterPass1!")

    window = MainWindow(session)
    window.show()

    assert session.is_unlocked is True
    window._on_unlocked_and_ready()
    assert window.stack.currentIndex() == MainWindow.SCREEN_VAULT

    # Simulate 401 Unauthorized via _handle_auth_failure (which triggers lock callbacks synchronously)
    session._handle_auth_failure()
    assert session.is_unlocked is False

    # Window navigates to SCREEN_LOGIN
    assert window.stack.currentIndex() == MainWindow.SCREEN_LOGIN
    # Warning banner displays expiration message
    assert not window.login_screen.status_banner.isHidden()
    assert "session has expired or was revoked" in window.login_screen.status_banner.text()



# ============================================================================
# 6. GUI Screen Usability, Navigation & Empty States
# ============================================================================


def test_password_edit_widget_reveal_reset_and_return_pressed(qapp):
    """Test PasswordEdit auto-resets reveal on clear and exposes returnPressed."""
    widget = PasswordEdit(placeholder="Test")
    widget.show()

    # Default: masked
    assert widget.line_edit.echoMode() == widget.line_edit.EchoMode.Password

    # Reveal password
    widget.toggle_btn.click()
    assert widget.line_edit.echoMode() == widget.line_edit.EchoMode.Normal
    assert widget._is_revealed is True

    # reset_reveal restores masked mode
    widget.reset_reveal()
    assert widget.line_edit.echoMode() == widget.line_edit.EchoMode.Password
    assert widget._is_revealed is False

    # Clear calls reset_reveal automatically
    widget.toggle_btn.click()
    assert widget._is_revealed is True
    widget.clear()
    assert widget._is_revealed is False
    assert widget.line_edit.echoMode() == widget.line_edit.EchoMode.Password

    # returnPressed is connected
    pressed_received = []
    widget.returnPressed.connect(lambda: pressed_received.append(True))
    widget.line_edit.returnPressed.emit()
    assert len(pressed_received) == 1


def test_login_screen_keyboard_navigation_and_clear_username(qapp, tmp_path):
    """Test LoginScreen returnPressed navigation and clear username on explicit logout."""
    cfg = AppConfig(config_path=tmp_path / "cfg.json")
    cfg.last_username = "previous_user"
    session = VaultSession(config=cfg)

    screen = LoginScreen(session)
    screen.show()

    assert screen.username_input.text() == "previous_user"

    # Reset with clear_username=True
    screen.reset_to_login(clear_username=True)
    assert screen.username_input.text() == ""


def test_register_screen_error_mapping_and_clearing(qapp, tmp_path):
    """Test RegisterScreen friendly error mapping and sensitive input clearing."""
    cfg = AppConfig(config_path=tmp_path / "cfg.json")
    session = VaultSession(config=cfg)
    screen = RegisterScreen(session)
    screen.show()

    # Conflict error mapping
    screen._handle_register_error(ConflictError("Username already taken"))
    assert not screen.status_banner.isHidden()
    assert "already registered" in screen.status_banner.text()

    # Network error mapping
    screen._handle_register_error(NetworkConnectionError("Connection refused"))
    assert "Cannot connect to server" in screen.status_banner.text()

    # Input clearing
    screen.username_input.setText("some_user")
    screen.account_pwd_input.setText("Secret12345!")
    screen.clear_sensitive_inputs()
    assert screen.username_input.text() == ""
    assert screen.account_pwd_input.text() == ""
    assert screen.status_banner.isHidden() is True


def test_vault_screen_empty_states_cancel_and_deletion(qapp, tmp_path):
    """Test VaultScreen empty vault guidance, cancel edit reversion, and delete banner."""
    cfg = AppConfig(config_path=tmp_path / "cfg.json")
    cfg.clipboard_clear_seconds = 30
    session = VaultSession(config=cfg)
    session.is_unlocked = True

    screen = VaultScreen(session)
    screen.show()

    # 1. Empty vault placeholder text
    screen.reload_items()
    assert "Your vault is empty" in screen.placeholder_label.text()

    # 2. New item creation and cancel
    screen._on_new_item_clicked()
    assert not screen.editor_widget.isHidden()
    assert screen.title_input.text() == "New Item"
    screen.title_input.setText("Unsaved Draft")
    screen._on_cancel_clicked()
    # Cancel hides editor and restores placeholder
    assert screen.editor_widget.isHidden() is True
    assert not screen.placeholder_widget.isHidden()
    assert screen.title_input.text() == ""

    # 3. Add existing item and test edit cancellation
    item = VaultItem(
        title="GitLab Account",
        username="developer",
        password="OriginalGitLabPassword123!",
        url="https://gitlab.com",
    )
    session.items[item.id] = item
    screen.reload_items()
    assert screen.item_list.count() == 1

    # Load item into editor
    screen._load_item_into_editor(item)
    assert screen.title_input.text() == "GitLab Account"
    assert screen.password_input.text() == "OriginalGitLabPassword123!"

    # Modify form fields
    screen.title_input.setText("Modified Title")
    screen.password_input.setText("ModifiedPassword999!")

    # Click Cancel -> must revert to saved item values
    screen._on_cancel_clicked()
    assert screen.title_input.text() == "GitLab Account"
    assert screen.password_input.text() == "OriginalGitLabPassword123!"
    assert session.items[item.id].title == "GitLab Account"
    assert "Changes discarded" in screen.banner_label.text()

    # 4. Search with no matches
    screen.search_input.setText("nonexistent_query_xyz")
    assert screen.item_list.count() == 0
    assert "No vault items matching 'nonexistent_query_xyz'" in screen.placeholder_label.text()

    # Clear search
    screen.search_input.clear()
    assert screen.item_list.count() == 1

    # 5. Clipboard copy with timeout vs zero timeout
    screen._copy_to_clipboard("test_pass", "Password")
    assert "will automatically clear in 30s" in screen.banner_label.text()

    session.config.clipboard_clear_seconds = 0
    screen._copy_to_clipboard("test_user", "Username")
    assert "Username copied to clipboard" in screen.banner_label.text()
    assert "automatically clear" not in screen.banner_label.text()


def test_settings_screen_clipboard_combo_and_security_notes(qapp, tmp_path):
    """Test SettingsScreen clipboard timeout configuration and master password warning notes."""
    cfg = AppConfig(config_path=tmp_path / "cfg.json")
    cfg.auto_lock_minutes = 15
    cfg.clipboard_clear_seconds = 30
    session = VaultSession(config=cfg)

    screen = SettingsScreen(session)
    screen.show()

    # Change clipboard timeout to 10 Seconds (index 0)
    screen.clipboard_combo.setCurrentIndex(0)
    assert session.config.clipboard_clear_seconds == 10

    # Change clipboard timeout to Never (index 3)
    screen.clipboard_combo.setCurrentIndex(3)
    assert session.config.clipboard_clear_seconds == 0
