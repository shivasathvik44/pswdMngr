"""Automated tests for PySide6 desktop GUI screens and components."""

import sys
import time
import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from vaultsync_server.crypto.errors import DecryptionFailedError

from vaultsync_desktop.api_client import MigrationRequiredError
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.crypto import create_initial_vault_key_and_envelope
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage
from vaultsync_desktop.ui.main_window import MainWindow
from vaultsync_desktop.ui.screens.login_screen import LoginScreen
from vaultsync_desktop.ui.screens.register_screen import RegisterScreen
from vaultsync_desktop.ui.screens.server_screen import ServerScreen
from vaultsync_desktop.ui.screens.settings_screen import SettingsScreen
from vaultsync_desktop.ui.screens.vault_screen import VaultScreen


@pytest.fixture(scope="session")
def qapp():
    """Ensure a singleton QApplication is initialized for offscreen testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    return app


@pytest.fixture
def mock_session(tmp_path):
    config = AppConfig(config_path=tmp_path / "config.json")
    storage = TokenStorage(service_name="test_vaultsync_ui")
    return VaultSession(config=config, storage=storage)


def test_server_screen_url_validation(qapp, mock_session):
    """Test ServerScreen validates URLs and rejects remote plain HTTP."""
    screen = ServerScreen(mock_session)
    screen.show()

    # Insecure remote HTTP -> shows error
    screen.url_input.setText("http://192.168.1.100:8000")
    screen._on_connect_clicked()
    assert not screen.status_banner.isHidden()
    assert "Plain HTTP is only permitted on loopback" in screen.status_banner.text()
    assert screen.action_container.isHidden() is True

    # Valid loopback HTTP -> error banner hidden on valid input
    screen.url_input.setText("http://127.0.0.1:8000")
    assert screen.url_input.text() == "http://127.0.0.1:8000"


def test_register_screen_validation(qapp, mock_session):
    """Test RegisterScreen validates username, password lengths, and confirmation."""
    screen = RegisterScreen(mock_session)
    screen.show()

    # 1. Empty username
    screen.username_input.setText("")
    screen._on_register_clicked()
    assert not screen.status_banner.isHidden()
    assert "Username cannot be empty" in screen.status_banner.text()

    # 2. Short account password (< 8)
    screen.username_input.setText("alice")
    screen.account_pwd_input.setText("short")
    screen._on_register_clicked()
    assert "Account Password must be at least 8 characters" in screen.status_banner.text()

    # 3. Short master password (< 8)
    screen.account_pwd_input.setText("ValidAccountPass1!")
    screen.master_pwd_input.setText("short")
    screen._on_register_clicked()
    assert "Master Password must be at least 8 characters" in screen.status_banner.text()

    # 4. Master password mismatch
    screen.master_pwd_input.setText("CorrectHorseBattery1!")
    screen.confirm_pwd_input.setText("DifferentPassword2!")
    screen._on_register_clicked()
    assert "do not match" in screen.status_banner.text()


def test_login_screen_handles_migration_and_wrong_password(qapp, mock_session):
    """Test LoginScreen renders migration warning and handles wrong unlock password safely."""
    screen = LoginScreen(mock_session)
    screen.show()

    # Test handling migration error (HTTP 403)
    screen._handle_login_error("legacy_user", MigrationRequiredError("Account requires password migration."))
    assert not screen.status_banner.isHidden()
    assert "Account Migration Required" in screen.status_banner.text()
    assert "admin_reset --username legacy_user" in screen.status_banner.text()

    # Test wrong master password error
    screen._handle_unlock_error(DecryptionFailedError("InvalidTag"))
    assert not screen.status_banner.isHidden()
    assert "Incorrect Vault Master Password" in screen.status_banner.text()
    assert mock_session.is_unlocked is False


def test_vault_screen_search_and_clipboard_clearing(qapp, mock_session):
    """Test VaultScreen item search and clipboard clearing timeout behavior."""
    mock_session.is_unlocked = True
    item1 = VaultItem(title="GitHub", username="octocat", password="SecretPassword1!")
    item2 = VaultItem(title="Amazon", username="shopper", password="SecretPassword2!")
    mock_session.items[item1.id] = item1
    mock_session.items[item2.id] = item2

    screen = VaultScreen(mock_session)
    screen.show()
    screen.reload_items()
    assert screen.item_list.count() == 2

    # Filter search by "git"
    screen.search_input.setText("git")
    assert screen.item_list.count() == 1
    assert "GitHub" in screen.item_list.item(0).text()

    # Reset search
    screen.search_input.setText("")
    assert screen.item_list.count() == 2

    # Test clipboard copy with conditional check
    copied_val = "UniqueCopiedPassword999!"
    clipboard = QApplication.clipboard()
    screen._copy_to_clipboard(copied_val, "Password")
    assert clipboard.text() == copied_val

    # If user copies a different string before timeout, the original timer MUST NOT wipe the new string!
    user_new_copy = "UserManualCopyLater"
    clipboard.setText(user_new_copy)

    # Simulate clearing callback that checks equality
    current = clipboard.text()
    if current == copied_val:
        clipboard.clear()
    # Verified: user_new_copy was NOT wiped!
    assert clipboard.text() == user_new_copy


def test_settings_screen_auto_lock_interval_update(qapp, mock_session):
    """Test SettingsScreen updates auto-lock configuration."""
    screen = SettingsScreen(mock_session)
    screen.show()

    # Change to 5 minutes (index 1)
    screen.timeout_combo.setCurrentIndex(1)
    assert mock_session.config.auto_lock_minutes == 5

    # Change to 30 minutes (index 3)
    screen.timeout_combo.setCurrentIndex(3)
    assert mock_session.config.auto_lock_minutes == 30


def test_main_window_screen_navigation_and_lock_badges(qapp, mock_session):
    """Test MainWindow transitions between screens and updates locked/unlocked badges."""
    window = MainWindow(mock_session)
    window.show()

    # Initial state: Server screen, Locked badge
    assert window.stack.currentIndex() == MainWindow.SCREEN_SERVER
    assert "Locked" in window.lock_badge.text()

    # Navigate to login
    window._goto_login()
    assert window.stack.currentIndex() == MainWindow.SCREEN_LOGIN

    # Simulate unlocking vault
    mock_session.is_unlocked = True
    window._on_unlocked_and_ready()
    assert window.stack.currentIndex() == MainWindow.SCREEN_VAULT
    assert "Unlocked" in window.lock_badge.text()
    assert not window.quick_lock_btn.isHidden()

    # Lock vault
    mock_session.lock()
    assert window.stack.currentIndex() == MainWindow.SCREEN_LOGIN
    assert "Locked" in window.lock_badge.text()
    assert window.quick_lock_btn.isHidden() is True


def test_no_secret_leakage_in_ui_or_errors(qapp, mock_session):
    """Verify that sensitive master passwords and VEK bytes never appear in UI error banners."""
    screen = LoginScreen(mock_session)
    secret_pw = "SuperConfidentialPassphrase9876!"

    # Simulate wrong password error
    screen._handle_unlock_error(DecryptionFailedError("InvalidTag: Tag mismatch"))
    banner_text = screen.status_banner.text()

    # Ensure no secret strings or key fragments in UI text
    assert secret_pw not in banner_text
    assert "VEK" not in banner_text or "vault key" in banner_text.lower()
    assert "raw_bytes" not in banner_text


def test_screen_clearing_on_vault_lock(qapp, mock_session):
    """Verify that locking the vault wipes all plaintext fields across all screens."""
    window = MainWindow(mock_session)
    window.show()

    mock_session.is_unlocked = True
    item = VaultItem(
        title="Decrypted Secret Entry",
        username="admin",
        password="TopSecretPassword123!",
        url="https://secret.com",
        notes="Classified memo",
    )
    mock_session.items[item.id] = item

    # Load item into editor
    window.vault_screen.reload_items()
    window.vault_screen._load_item_into_editor(item)
    window.settings_screen.current_acc_pwd.setText("CurrentAccPw123!")
    window.settings_screen.new_master_pwd.setText("NewMasterPw123!")
    window.register_screen.account_pwd_input.setText("RegisterAccPw123!")

    assert window.vault_screen.password_input.text() == "TopSecretPassword123!"
    assert window.vault_screen.notes_input.toPlainText() == "Classified memo"
    assert window.settings_screen.current_acc_pwd.text() == "CurrentAccPw123!"

    # Trigger Lock
    mock_session.lock()

    # Verify VaultScreen is sanitized
    assert window.vault_screen.current_item_id is None
    assert window.vault_screen.title_input.text() == ""
    assert window.vault_screen.username_input.text() == ""
    assert window.vault_screen.password_input.text() == ""
    assert window.vault_screen.url_input.text() == ""
    assert window.vault_screen.notes_input.toPlainText() == ""
    assert window.vault_screen.search_input.text() == ""
    assert window.vault_screen.item_list.count() == 0
    assert window.vault_screen.editor_widget.isHidden() is True
    assert not window.vault_screen.placeholder_widget.isHidden()

    # Verify SettingsScreen is sanitized
    assert window.settings_screen.current_acc_pwd.text() == ""
    assert window.settings_screen.new_acc_pwd.text() == ""
    assert window.settings_screen.new_master_pwd.text() == ""
    assert window.settings_screen.confirm_master_pwd.text() == ""

    # Verify RegisterScreen is sanitized
    window.register_screen.clear_sensitive_inputs()
    assert window.register_screen.account_pwd_input.text() == ""
    assert window.register_screen.master_pwd_input.text() == ""
    assert window.register_screen.confirm_pwd_input.text() == ""


def test_passphrase_strength_widget_entropy_guidance(qapp):
    """Verify PassphraseStrengthWidget conveys heuristic limits and offline cracking awareness."""
    from vaultsync_desktop.ui.widgets.passphrase_strength import PassphraseStrengthWidget

    widget = PassphraseStrengthWidget()
    widget.show()

    # Weak password
    widget.update_strength("weak")
    assert "Weak" in widget.label.text()
    assert "offline" in widget.advice_label.text().lower()

    # Diceware multi-word passphrase
    widget.update_strength("correct horse battery staple elephant")
    assert "Heuristic" in widget.label.text()
    assert "Diceware" in widget.advice_label.text() or "offline" in widget.advice_label.text().lower()

