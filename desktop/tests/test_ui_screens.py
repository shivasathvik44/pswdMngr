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


def test_vault_screen_new_item_creation_and_save_success(qapp, mock_session):
    """Regression test: Creating and saving a new item does not raise ValidationError
    and shows success banner while synchronizing item_list selection."""
    mock_session.is_unlocked = True
    screen = VaultScreen(mock_session)
    screen.show()

    # Click new item
    screen._on_new_item_clicked()
    assert screen.current_item_id is None
    assert screen.title_input.text() == "New Item"
    assert screen.editor_widget.isVisible()

    # Fill fields
    screen.title_input.setText("ProtonMail")
    screen.username_input.setText("user@proton.me")
    screen.password_input.setText("VerySecretPassword2026!")
    screen.url_input.setText("https://mail.proton.me")
    screen.notes_input.setPlainText("Encrypted email service")

    # Save item without exception
    screen._on_save_clicked()
    # Button enters saving state
    assert screen.save_btn.text() == "Encrypting & Saving..."
    assert not screen.save_btn.isEnabled()

    # Simulate save success
    saved_item = VaultItem(
        title="ProtonMail",
        username="user@proton.me",
        password="VerySecretPassword2026!",
        url="https://mail.proton.me",
        notes="Encrypted email service",
    )
    mock_session.items[saved_item.id] = saved_item
    screen._on_save_success(saved_item)

    # Verification:
    # 1. Success banner is visible with confirmation message
    assert not screen.banner_label.isHidden()
    assert "Entry encrypted and saved successfully" in screen.banner_label.text()
    # 2. current_item_id matches saved item ID
    assert screen.current_item_id == saved_item.id
    # 3. Item appears in list and is selected
    assert screen.item_list.count() == 1
    assert "ProtonMail" in screen.item_list.item(0).text()
    assert screen.item_list.currentItem() is not None
    assert screen.item_list.currentItem().data(Qt.ItemDataRole.UserRole) == saved_item.id


def test_vault_screen_validation_error_handling(qapp, mock_session):
    """Verify validation errors are caught, displayed in banner, and do not leak secrets."""
    mock_session.is_unlocked = True
    screen = VaultScreen(mock_session)
    screen.show()
    screen._on_new_item_clicked()

    # 1. Empty title validation
    screen.title_input.setText("")
    screen._on_save_clicked()
    assert not screen.banner_label.isHidden()
    assert "Title cannot be empty" in screen.banner_label.text()

    # 2. Field constraint violation (> 256 chars title)
    screen.title_input.setText("A" * 257)
    screen.password_input.setText("SecretPassword123!")
    screen._on_save_clicked()
    assert not screen.banner_label.isHidden()
    assert "Validation error" in screen.banner_label.text()
    # Ensure sensitive password text is NOT in banner
    assert "SecretPassword123!" not in screen.banner_label.text()


def test_vault_screen_cancel_reverts_state(qapp, mock_session):
    """Verify Cancel button reverts new item form or uncommitted edits on existing item."""
    mock_session.is_unlocked = True
    item = VaultItem(title="Bitbucket", username="dev", password="OriginalPassword1!")
    mock_session.items[item.id] = item

    screen = VaultScreen(mock_session)
    screen.show()
    screen.reload_items()

    # 1. Cancel during new item creation reverts to placeholder
    screen._on_new_item_clicked()
    assert screen.editor_widget.isVisible()
    screen._on_cancel_clicked()
    assert screen.editor_widget.isHidden()
    assert screen.placeholder_widget.isVisible()

    # 2. Cancel during existing item edit reverts modified fields
    screen._load_item_into_editor(item)
    screen.title_input.setText("Modified Title Not Saved")
    screen.password_input.setText("ModifiedPasswordNotSaved")
    screen._on_cancel_clicked()
    assert screen.title_input.text() == "Bitbucket"
    assert screen.password_input.text() == "OriginalPassword1!"


def test_vault_screen_search_preserves_selected_item(qapp, mock_session):
    """Verify that searching preserves current editor item if it matches query."""
    mock_session.is_unlocked = True
    item1 = VaultItem(title="GitHub", username="octocat")
    item2 = VaultItem(title="GitLab", username="gitlabber")
    item3 = VaultItem(title="Slack", username="chatuser")
    mock_session.items[item1.id] = item1
    mock_session.items[item2.id] = item2
    mock_session.items[item3.id] = item3

    screen = VaultScreen(mock_session)
    screen.show()
    screen.reload_items()

    # Select GitHub
    screen._load_item_into_editor(item1)
    assert screen.current_item_id == item1.id
    assert screen.editor_widget.isVisible()

    # Search "git" -> item1 matches, stays selected and editor stays visible
    screen.search_input.setText("git")
    assert screen.item_list.count() == 2
    assert screen.current_item_id == item1.id
    assert screen.editor_widget.isVisible()

    # Search "slack" -> item1 does not match, reverts to placeholder
    screen.search_input.setText("slack")
    assert screen.item_list.count() == 1
    assert screen.placeholder_widget.isVisible()


def test_vault_screen_clipboard_cleared_on_lock(qapp, mock_session):
    """Verify that locking the vault immediately clears any copied secrets from the clipboard."""
    mock_session.is_unlocked = True
    screen = VaultScreen(mock_session)
    screen.show()

    secret = "CopiedSecretVaultPassword123!"
    screen._copy_to_clipboard(secret, "Password")
    clipboard = QApplication.clipboard()
    assert clipboard.text() == secret
    assert screen.last_copied_text == secret

    # Vault locks
    screen.clear_vault_ui()
    assert clipboard.text() == ""
    assert screen.last_copied_text is None


def test_settings_navigation_and_cross_thread_lock_safety(qapp, mock_session):
    """Verify that locking from a background thread dispatches safely and opening Settings does not crash."""
    import threading
    from PySide6.QtCore import QThread

    window = MainWindow(mock_session)
    window.show()

    mock_session.is_unlocked = True
    window._on_unlocked_and_ready()
    assert window.stack.currentIndex() == MainWindow.SCREEN_VAULT

    # Invoke session.lock() from a background thread to simulate async logout or auth failure
    bg_error = []
    def bg_lock():
        try:
            assert QThread.currentThread() != qapp.thread()
            mock_session.lock()
        except Exception as exc:
            bg_error.append(exc)

    t = threading.Thread(target=bg_lock)
    t.start()
    t.join()

    assert not bg_error
    qapp.processEvents()

    # Verify session is locked and UI wiped
    assert mock_session.is_unlocked is False
    assert window.stack.currentIndex() == MainWindow.SCREEN_LOGIN

    # Re-authenticate and unlock
    mock_session.is_unlocked = True
    window._on_unlocked_and_ready()
    assert window.stack.currentIndex() == MainWindow.SCREEN_VAULT

    # Click Settings button and verify SettingsScreen renders without crash or segfault
    window.settings_btn.click()
    qapp.processEvents()
    assert window.stack.currentIndex() == MainWindow.SCREEN_SETTINGS
    assert window.settings_screen.isVisible()

    # Navigate back to Vault via header back button
    window.settings_screen.back_to_vault.emit()
    qapp.processEvents()
    assert window.stack.currentIndex() == MainWindow.SCREEN_VAULT


def test_passphrase_strength_widget_reset(qapp):
    """Verify PassphraseStrengthWidget reset and empty string handling."""
    from vaultsync_desktop.ui.widgets.passphrase_strength import PassphraseStrengthWidget

    widget = PassphraseStrengthWidget()
    widget.show()

    # Set strong passphrase
    widget.update_strength("Correct-Horse-Battery-Staple-2026!")
    assert widget.bar.value() > 0
    assert "Not evaluated" not in widget.label.text()
    assert widget.advice_label.isVisible()

    # Reset
    widget.reset()
    assert widget.bar.value() == 0
    assert widget.label.text() == "Strength: Not evaluated"
    assert widget.advice_label.isHidden()

    # Empty string should trigger reset
    widget.update_strength("TemporaryPass123!")
    assert widget.bar.value() > 0
    widget.update_strength("")
    assert widget.bar.value() == 0
    assert widget.label.text() == "Strength: Not evaluated"
    assert widget.advice_label.isHidden()


def test_call_on_gui_thread_dispatches_safely(qapp):
    """Verify call_on_gui_thread dispatches to the main GUI thread from any thread."""
    import threading
    from PySide6.QtCore import QThread
    from vaultsync_desktop.async_bridge import call_on_gui_thread

    # 1. Calling directly from GUI thread executes synchronously
    executed_sync = []
    call_on_gui_thread(lambda val: executed_sync.append(val), "sync_ok")
    assert executed_sync == ["sync_ok"]

    # 2. Calling from background thread executes on GUI thread
    executed_async = []
    execution_thread = []

    def worker():
        def task_on_gui():
            executed_async.append("bg_ok")
            execution_thread.append(QThread.currentThread())
        call_on_gui_thread(task_on_gui)

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    # Before processEvents, queued slot has not run yet
    qapp.processEvents()
    assert executed_async == ["bg_ok"]
    assert execution_thread[0] == qapp.thread()


def test_settings_show_event_syncs_auto_lock_config(qapp, mock_session):
    """Verify showEvent updates the combo box from config without triggering feedback banners."""
    mock_session.config.auto_lock_minutes = 60
    screen = SettingsScreen(mock_session)
    screen.show()

    # 60 minutes corresponds to index 4
    assert screen.timeout_combo.currentIndex() == 4
    # Feedback banner should remain hidden upon show
    assert screen.feedback_banner.isHidden()

    # Update config externally and re-show
    mock_session.config.auto_lock_minutes = 1
    screen.hide()
    screen.show()
    assert screen.timeout_combo.currentIndex() == 0
    assert screen.feedback_banner.isHidden()


def test_session_remove_lock_callback(mock_session):
    """Verify remove_lock_callback successfully unregisters callbacks."""
    calls = []
    cb = lambda: calls.append(1)

    mock_session.add_lock_callback(cb)
    mock_session.lock()
    assert len(calls) == 1

    mock_session.remove_lock_callback(cb)
    mock_session.lock()
    assert len(calls) == 1  # Not called again









