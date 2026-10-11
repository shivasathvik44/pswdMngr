"""Registration screen implementing the Two-Credential architecture."""

import asyncio
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from vaultsync_desktop.async_bridge import run_async
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.ui.widgets.passphrase_strength import PassphraseStrengthWidget
from vaultsync_desktop.ui.widgets.password_edit import PasswordEdit


class RegisterScreen(QWidget):
    """Screen for creating an account and initializing an encrypted vault."""

    registered_success = Signal()
    switch_to_login = Signal()

    def __init__(self, session: VaultSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 20, 40, 20)

        card = QFrame()
        card.setProperty("class", "card")
        card.setFixedWidth(560)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(12)

        # Title
        title = QLabel("Create VaultSync Account")
        title.setProperty("class", "heading")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        # Two-Credential Architecture Explanatory Banner
        banner = QLabel(
            "<b>Two-Credential Architecture:</b><br/>"
            "• <b>Account Password:</b> Authenticates you to the server API. Never derives vault keys.<br/>"
            "• <b>Vault Master Password:</b> Used strictly on this device to encrypt your vault. "
            "Never transmitted to or stored by the server under any circumstance."
        )
        banner.setProperty("class", "info-banner")
        banner.setWordWrap(True)
        banner.setStyleSheet(
            "background-color: #1E2D4A; border: 1px solid #3584E4; border-radius: 6px; padding: 10px; color: #BDDCFF;"
        )
        card_layout.addWidget(banner)

        # Username
        card_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g. alice")
        card_layout.addWidget(self.username_input)

        # Account Password
        card_layout.addWidget(QLabel("1. Server Account Password (min 8 chars):"))
        self.account_pwd_input = PasswordEdit(placeholder="Password for server login")
        card_layout.addWidget(self.account_pwd_input)

        # Vault Master Password
        card_layout.addWidget(QLabel("2. Vault Master Password (used to encrypt vault locally):"))
        self.master_pwd_input = PasswordEdit(placeholder="Passphrase for vault encryption")
        self.master_pwd_input.textChanged.connect(self._on_master_pwd_changed)
        card_layout.addWidget(self.master_pwd_input)

        # Entropy / Passphrase Strength Guide
        self.strength_widget = PassphraseStrengthWidget()
        card_layout.addWidget(self.strength_widget)

        # Confirm Master Password
        card_layout.addWidget(QLabel("Confirm Vault Master Password:"))
        self.confirm_pwd_input = PasswordEdit(placeholder="Re-enter vault master password")
        card_layout.addWidget(self.confirm_pwd_input)

        # Status Banner
        self.status_banner = QLabel()
        self.status_banner.setWordWrap(True)
        self.status_banner.hide()
        card_layout.addWidget(self.status_banner)

        # Register Button
        self.submit_btn = QPushButton("Create Account & Encrypt Vault")
        self.submit_btn.setProperty("class", "primary")
        self.submit_btn.clicked.connect(self._on_register_clicked)
        card_layout.addWidget(self.submit_btn)

        # Login switch button
        footer_layout = QHBoxLayout()
        footer_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_link = QPushButton("Already have an account? Log In")
        login_link.setProperty("class", "secondary")
        login_link.clicked.connect(self.switch_to_login.emit)
        footer_layout.addWidget(login_link)
        card_layout.addLayout(footer_layout)

        layout.addWidget(card)

    def _on_master_pwd_changed(self, text: str) -> None:
        self.strength_widget.update_strength(text)

    def _on_register_clicked(self) -> None:
        username = self.username_input.text().strip()
        account_pwd = self.account_pwd_input.text()
        master_pwd = self.master_pwd_input.text()
        confirm_pwd = self.confirm_pwd_input.text()

        # Input validation
        if not username:
            self._show_error("Username cannot be empty.")
            return
        if len(account_pwd) < 8:
            self._show_error("Server Account Password must be at least 8 characters.")
            return
        if len(master_pwd) < 8:
            self._show_error("Vault Master Password must be at least 8 characters.")
            return
        if master_pwd != confirm_pwd:
            self._show_error("Vault Master Passwords do not match.")
            return

        self.submit_btn.setEnabled(False)
        self.submit_btn.setText("Deriving Keys & Registering...")
        self.status_banner.hide()

        async def _do_register_flow():
            await self.session.register_account(
                username=username,
                account_password=account_pwd,
                vault_master_password=master_pwd,
            )
            # Log in and unlock immediately after registration
            await self.session.login_account(username=username, account_password=account_pwd)
            await self.session.unlock_vault(master_pwd)

        run_async(
            _do_register_flow(),
            on_success=lambda _: self.registered_success.emit(),
            on_error=lambda exc: self._show_error(f"Registration failed: {exc}"),
            on_finally=self._on_register_finally,
        )

    def _on_register_finally(self) -> None:
        self.submit_btn.setEnabled(True)
        self.submit_btn.setText("Create Account & Encrypt Vault")

    def _show_error(self, message: str) -> None:
        self.status_banner.setText(message)
        self.status_banner.setStyleSheet(
            "background-color: #3D1C1D; border: 1px solid #E01B24; border-radius: 6px; padding: 10px; color: #FFB3B6;"
        )
        self.status_banner.show()
