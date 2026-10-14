"""Settings and security screen."""

import asyncio
from typing import Any
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from vaultsync_desktop.async_bridge import run_async
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.ui.widgets.passphrase_strength import PassphraseStrengthWidget
from vaultsync_desktop.ui.widgets.password_edit import PasswordEdit


class SettingsScreen(QWidget):
    """Settings screen for credential rotation, auto-lock configuration, and manual locking."""

    back_to_vault = Signal()
    request_lock = Signal()
    request_logout = Signal()

    def __init__(self, session: VaultSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self.session.add_lock_callback(self.clear_sensitive_inputs)
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget(scroll)
        layout = QVBoxLayout(container)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Header with Back button
        header_row = QHBoxLayout()
        back_btn = QPushButton("← Back to Vault")
        back_btn.setProperty("class", "secondary")
        back_btn.clicked.connect(self.back_to_vault.emit)

        title = QLabel("Security & Settings")
        title.setProperty("class", "heading")

        header_row.addWidget(back_btn)
        header_row.addWidget(title)
        header_row.addStretch()
        layout.addLayout(header_row)

        # Feedback banner
        self.feedback_banner = QLabel(container)
        self.feedback_banner.setWordWrap(True)
        self.feedback_banner.hide()
        layout.addWidget(self.feedback_banner)

        # --------------------------------------------------------------------
        # Section 1: Auto-Lock & Clipboard Settings
        # --------------------------------------------------------------------
        sec_lock = QFrame()
        sec_lock.setProperty("class", "card")
        sec_lock_layout = QVBoxLayout(sec_lock)
        sec_lock_layout.setSpacing(12)

        lbl_lock_title = QLabel("Locking & Security Preferences")
        lbl_lock_title.setProperty("class", "subheading")
        sec_lock_layout.addWidget(lbl_lock_title)

        row_timeout = QHBoxLayout()
        row_timeout.addWidget(QLabel("Auto-Lock Inactivity Timeout:"))
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems([
            "1 Minute",
            "5 Minutes",
            "15 Minutes",
            "30 Minutes",
            "60 Minutes",
        ])
        # Map current config
        mins = self.session.config.auto_lock_minutes
        idx_map = {1: 0, 5: 1, 15: 2, 30: 3, 60: 4}
        self.timeout_combo.setCurrentIndex(idx_map.get(mins, 2))
        self.timeout_combo.currentIndexChanged.connect(self._on_timeout_changed)
        row_timeout.addWidget(self.timeout_combo)
        sec_lock_layout.addLayout(row_timeout)

        row_clip = QHBoxLayout()
        row_clip.addWidget(QLabel("Clear Clipboard Automatically:"))
        self.clipboard_combo = QComboBox()
        self.clipboard_combo.addItems([
            "10 Seconds",
            "30 Seconds",
            "60 Seconds",
            "Never",
        ])
        secs = self.session.config.clipboard_clear_seconds
        clip_idx_map = {10: 0, 30: 1, 60: 2, 0: 3}
        self.clipboard_combo.setCurrentIndex(clip_idx_map.get(secs, 1))
        self.clipboard_combo.currentIndexChanged.connect(self._on_clipboard_timeout_changed)
        row_clip.addWidget(self.clipboard_combo)
        sec_lock_layout.addLayout(row_clip)

        btn_row = QHBoxLayout()
        lock_now_btn = QPushButton("🔒 Lock Vault Now")
        lock_now_btn.setProperty("class", "primary")
        lock_now_btn.clicked.connect(self.request_lock.emit)

        logout_btn = QPushButton("🚪 Log Out")
        logout_btn.setProperty("class", "danger")
        logout_btn.clicked.connect(self.request_logout.emit)

        btn_row.addWidget(lock_now_btn)
        btn_row.addWidget(logout_btn)
        btn_row.addStretch()
        sec_lock_layout.addLayout(btn_row)

        layout.addWidget(sec_lock)

        # --------------------------------------------------------------------
        # Section 2: Change Server Account Password
        # --------------------------------------------------------------------
        sec_acc = QFrame()
        sec_acc.setProperty("class", "card")
        sec_acc_layout = QVBoxLayout(sec_acc)
        sec_acc_layout.setSpacing(10)

        lbl_acc_title = QLabel("Change Server Account Password")
        lbl_acc_title.setProperty("class", "subheading")
        sec_acc_layout.addWidget(lbl_acc_title)

        acc_desc = QLabel(
            "Updates your server login credential. Leaves vault encryption keys and "
            "all encrypted records completely untouched.<br/>"
            "<b>Note:</b> Changing your account password does NOT reset or recover a forgotten master password."
        )
        acc_desc.setProperty("class", "caption")
        acc_desc.setTextFormat(Qt.TextFormat.RichText)
        acc_desc.setWordWrap(True)
        sec_acc_layout.addWidget(acc_desc)

        sec_acc_layout.addWidget(QLabel("Current Account Password:"))
        self.current_acc_pwd = PasswordEdit(placeholder="Enter current account password")
        sec_acc_layout.addWidget(self.current_acc_pwd)

        sec_acc_layout.addWidget(QLabel("New Account Password (min 8 chars):"))
        self.new_acc_pwd = PasswordEdit(placeholder="Enter new account password")
        sec_acc_layout.addWidget(self.new_acc_pwd)

        self.current_acc_pwd.returnPressed.connect(self.new_acc_pwd.setFocus)
        self.new_acc_pwd.returnPressed.connect(self._on_change_account_pwd_clicked)

        self.save_acc_pwd_btn = QPushButton("Update Account Password")
        self.save_acc_pwd_btn.clicked.connect(self._on_change_account_pwd_clicked)
        sec_acc_layout.addWidget(self.save_acc_pwd_btn)

        layout.addWidget(sec_acc)

        # --------------------------------------------------------------------
        # Section 3: Rotate Vault Master Password
        # --------------------------------------------------------------------
        sec_master = QFrame()
        sec_master.setProperty("class", "card")
        sec_master_layout = QVBoxLayout(sec_master)
        sec_master_layout.setSpacing(10)

        lbl_master_title = QLabel("Rotate Vault Master Password")
        lbl_master_title.setProperty("class", "subheading")
        sec_master_layout.addWidget(lbl_master_title)

        master_desc = QLabel(
            "<b>Re-wrapping Architecture:</b> Re-encrypts your 256-bit Vault Encryption Key (VEK) "
            "with a new salt and KEK derived from the new master password.<br/>"
            "<i>Records do not need to be re-encrypted because the underlying VEK is preserved.</i><br/><br/>"
            "<b>Warning:</b> If you lose your master password, your vault is <b>permanently unrecoverable</b>. "
            "Changing your account password cannot recover a forgotten master password."
        )
        master_desc.setProperty("class", "warning-banner")
        master_desc.setTextFormat(Qt.TextFormat.RichText)
        master_desc.setStyleSheet(
            "background-color: #382A15; border: 1px solid #E5A50A; border-radius: 6px; padding: 10px; color: #FFDE8A;"
        )
        master_desc.setWordWrap(True)
        sec_master_layout.addWidget(master_desc)

        sec_master_layout.addWidget(QLabel("New Vault Master Password:"))
        self.new_master_pwd = PasswordEdit(placeholder="Enter new vault master password")
        self.new_master_pwd.textChanged.connect(self._on_new_master_pwd_changed)
        sec_master_layout.addWidget(self.new_master_pwd)

        self.master_strength = PassphraseStrengthWidget()
        sec_master_layout.addWidget(self.master_strength)

        sec_master_layout.addWidget(QLabel("Confirm New Master Password:"))
        self.confirm_master_pwd = PasswordEdit(placeholder="Confirm new master password")
        sec_master_layout.addWidget(self.confirm_master_pwd)

        self.new_master_pwd.returnPressed.connect(self.confirm_master_pwd.setFocus)
        self.confirm_master_pwd.returnPressed.connect(self._on_rotate_master_pwd_clicked)

        self.save_master_pwd_btn = QPushButton("Rotate Master Password (Re-wrap VEK)")
        self.save_master_pwd_btn.clicked.connect(self._on_rotate_master_pwd_clicked)
        sec_master_layout.addWidget(self.save_master_pwd_btn)

        layout.addWidget(sec_master)


        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def showEvent(self, event) -> None:
        """Synchronize displayed timeout with current session config on screen show."""
        super().showEvent(event)
        mins = self.session.config.auto_lock_minutes
        idx_map = {1: 0, 5: 1, 15: 2, 30: 3, 60: 4}
        self.timeout_combo.blockSignals(True)
        self.timeout_combo.setCurrentIndex(idx_map.get(mins, 2))
        self.timeout_combo.blockSignals(False)

        secs = self.session.config.clipboard_clear_seconds
        clip_idx_map = {10: 0, 30: 1, 60: 2, 0: 3}
        self.clipboard_combo.blockSignals(True)
        self.clipboard_combo.setCurrentIndex(clip_idx_map.get(secs, 1))
        self.clipboard_combo.blockSignals(False)

    def _on_timeout_changed(self, idx: int) -> None:
        mins_map = {0: 1, 1: 5, 2: 15, 3: 30, 4: 60}
        self.session.config.auto_lock_minutes = mins_map.get(idx, 15)
        self.session.config.save()
        self._show_feedback("Auto-lock timeout updated.", is_error=False)

    def _on_clipboard_timeout_changed(self, idx: int) -> None:
        secs_map = {0: 10, 1: 30, 2: 60, 3: 0}
        self.session.config.clipboard_clear_seconds = secs_map.get(idx, 30)
        self.session.config.save()
        self._show_feedback("Clipboard timeout updated.", is_error=False)


    def _on_new_master_pwd_changed(self, text: str) -> None:
        self.master_strength.update_strength(text)

    def _on_change_account_pwd_clicked(self) -> None:
        cur_pwd = self.current_acc_pwd.text()
        new_pwd = self.new_acc_pwd.text()

        if not cur_pwd or not new_pwd:
            self._show_feedback("Please enter both current and new account passwords.", is_error=True)
            return
        if len(new_pwd) < 8:
            self._show_feedback("New account password must be at least 8 characters.", is_error=True)
            return

        self.save_acc_pwd_btn.setEnabled(False)
        run_async(
            self.session.change_account_password(cur_pwd, new_pwd),
            on_success=self._on_acc_pwd_success,
            on_error=lambda exc: self._show_feedback(f"Failed to update account password: {exc}", is_error=True),
            on_finally=lambda: self.save_acc_pwd_btn.setEnabled(True),
        )

    def clear_sensitive_inputs(self) -> None:
        """Clear all sensitive password fields and feedback on vault lock."""
        self.current_acc_pwd.clear()
        self.new_acc_pwd.clear()
        self.new_master_pwd.clear()
        self.confirm_master_pwd.clear()
        self.feedback_banner.hide()
        self.master_strength.reset()

    def _on_acc_pwd_success(self, _: Any) -> None:
        if not self.session.is_authenticated:
            return
        self._show_feedback("✓ Account password updated successfully.", is_error=False)
        self.current_acc_pwd.clear()
        self.new_acc_pwd.clear()

    def _on_rotate_master_pwd_clicked(self) -> None:
        if not self.session.is_unlocked:
            return
        new_pwd = self.new_master_pwd.text()
        confirm_pwd = self.confirm_master_pwd.text()

        if not new_pwd:
            self._show_feedback("Please enter a new master password.", is_error=True)
            return
        if len(new_pwd) < 8:
            self._show_feedback("Master password must be at least 8 characters.", is_error=True)
            return
        if new_pwd != confirm_pwd:
            self._show_feedback("Master passwords do not match.", is_error=True)
            return

        self.save_master_pwd_btn.setEnabled(False)
        self.save_master_pwd_btn.setText("Deriving Key & Re-wrapping VEK...")

        run_async(
            self.session.rotate_vault_master_password(new_pwd),
            on_success=self._on_rotate_master_pwd_success,
            on_error=lambda exc: self._show_feedback(f"Failed to rotate master password: {exc}", is_error=True) if self.session.is_unlocked else None,
            on_finally=self._on_rotate_master_pwd_finally,
        )

    def _on_rotate_master_pwd_success(self, _: Any) -> None:
        if not self.session.is_unlocked:
            return
        self._show_feedback("✓ Master password rotated successfully. VEK re-wrapped on server.", is_error=False)
        self.new_master_pwd.clear()
        self.confirm_master_pwd.clear()

    def _on_rotate_master_pwd_finally(self) -> None:
        self.save_master_pwd_btn.setEnabled(True)
        self.save_master_pwd_btn.setText("Rotate Master Password (Re-wrap VEK)")

    def _show_feedback(self, message: str, is_error: bool = False) -> None:
        self.feedback_banner.setText(message)
        if is_error:
            self.feedback_banner.setStyleSheet(
                "background-color: #3D1C1D; border: 1px solid #E01B24; border-radius: 6px; padding: 10px; color: #FFB3B6;"
            )
        else:
            self.feedback_banner.setStyleSheet(
                "background-color: #1A3626; border: 1px solid #2EC27E; border-radius: 6px; padding: 10px; color: #A6F0C6;"
            )
        self.feedback_banner.show()
