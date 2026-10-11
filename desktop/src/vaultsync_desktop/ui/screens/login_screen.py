"""Login and vault unlock screen keeping authentication and decryption separate."""

import asyncio
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from vaultsync_desktop.api_client import AuthenticationError, MigrationRequiredError, RateLimitError
from vaultsync_desktop.async_bridge import run_async
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.crypto import DecryptionFailedError
from vaultsync_desktop.ui.widgets.password_edit import PasswordEdit


class LoginScreen(QWidget):
    """Screen coordinating server authentication and local vault unlocking as distinct steps."""

    login_unlocked_success = Signal()
    switch_to_register = Signal()
    switch_to_server = Signal()

    def __init__(self, session: VaultSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.setContentsMargins(40, 20, 40, 20)

        self.card = QFrame()
        self.card.setProperty("class", "card")
        self.card.setFixedWidth(520)
        card_layout = QVBoxLayout(self.card)
        card_layout.setSpacing(14)

        # Title
        self.title_label = QLabel("Log In to VaultSync")
        self.title_label.setProperty("class", "heading")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(self.title_label)

        # Status / Error Banner
        self.status_banner = QLabel()
        self.status_banner.setWordWrap(True)
        self.status_banner.hide()
        card_layout.addWidget(self.status_banner)

        # Stacked pages: Page 0 = Account Login, Page 1 = Vault Unlock
        self.stack = QStackedWidget()

        # --- Page 0: Server Account Login ---
        self.page_login = QWidget()
        page_login_layout = QVBoxLayout(self.page_login)
        page_login_layout.setContentsMargins(0, 0, 0, 0)
        page_login_layout.setSpacing(12)

        page_login_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setText(self.session.config.last_username)
        self.username_input.setPlaceholderText("Enter username")
        page_login_layout.addWidget(self.username_input)

        page_login_layout.addWidget(QLabel("Server Account Password:"))
        self.account_pwd_input = PasswordEdit(placeholder="Enter server account password")
        page_login_layout.addWidget(self.account_pwd_input)

        self.login_btn = QPushButton("Log In with Account Password")
        self.login_btn.setProperty("class", "primary")
        self.login_btn.clicked.connect(self._on_login_clicked)
        page_login_layout.addWidget(self.login_btn)

        footer_layout = QHBoxLayout()
        reg_btn = QPushButton("Create New Account")
        reg_btn.setProperty("class", "secondary")
        reg_btn.clicked.connect(self.switch_to_register.emit)

        server_btn = QPushButton("Change Server")
        server_btn.setProperty("class", "secondary")
        server_btn.clicked.connect(self.switch_to_server.emit)

        footer_layout.addWidget(reg_btn)
        footer_layout.addWidget(server_btn)
        page_login_layout.addLayout(footer_layout)

        self.stack.addWidget(self.page_login)

        # --- Page 1: Local Vault Unlock ---
        self.page_unlock = QWidget()
        page_unlock_layout = QVBoxLayout(self.page_unlock)
        page_unlock_layout.setContentsMargins(0, 0, 0, 0)
        page_unlock_layout.setSpacing(12)

        self.user_greeting = QLabel("Authenticated as:")
        self.user_greeting.setStyleSheet("color: #3584E4; font-weight: 600;")
        page_unlock_layout.addWidget(self.user_greeting)

        unlock_notice = QLabel(
            "Enter your <b>Vault Master Password</b> to decrypt your local vault key. "
            "This credential is never transmitted to the server."
        )
        unlock_notice.setWordWrap(True)
        unlock_notice.setProperty("class", "caption")
        page_unlock_layout.addWidget(unlock_notice)

        page_unlock_layout.addWidget(QLabel("Vault Master Password:"))
        self.master_pwd_input = PasswordEdit(placeholder="Enter vault master password")
        page_unlock_layout.addWidget(self.master_pwd_input)

        self.unlock_btn = QPushButton("Unlock Vault")
        self.unlock_btn.setProperty("class", "primary")
        self.unlock_btn.clicked.connect(self._on_unlock_clicked)
        page_unlock_layout.addWidget(self.unlock_btn)

        unlock_footer = QHBoxLayout()
        logout_btn = QPushButton("Log Out / Switch Account")
        logout_btn.setProperty("class", "secondary")
        logout_btn.clicked.connect(self._on_logout_clicked)
        unlock_footer.addWidget(logout_btn)
        page_unlock_layout.addLayout(unlock_footer)

        self.stack.addWidget(self.page_unlock)

        card_layout.addWidget(self.stack)
        main_layout.addWidget(self.card)

    def reset_to_login(self) -> None:
        """Reset view to Step 1 (account login)."""
        self.stack.setCurrentIndex(0)
        self.title_label.setText("Log In to VaultSync")
        self.account_pwd_input.clear()
        self.master_pwd_input.clear()
        self.status_banner.hide()

    def show_unlock_prompt(self, username: str) -> None:
        """Transition view to Step 2 (vault unlock)."""
        self.stack.setCurrentIndex(1)
        self.title_label.setText("Unlock Vault")
        self.user_greeting.setText(f"Authenticated as: <b>{username}</b>")
        self.master_pwd_input.clear()
        self.status_banner.hide()

    def _on_login_clicked(self) -> None:
        username = self.username_input.text().strip()
        account_pwd = self.account_pwd_input.text()

        if not username or not account_pwd:
            self._show_error("Please enter both username and account password.")
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText("Authenticating...")
        self.status_banner.hide()

        run_async(
            self.session.login_account(username, account_pwd),
            on_success=lambda _: self.show_unlock_prompt(username),
            on_error=lambda exc: self._handle_login_error(username, exc),
            on_finally=self._on_login_finally,
        )

    def _handle_login_error(self, username: str, exc: Exception) -> None:
        if isinstance(exc, MigrationRequiredError):
            self._show_warning(
                f"<b>Account Migration Required:</b> Account '{username}' was registered under "
                "the legacy single-credential prototype.<br/>"
                "Please run administrative reset on the server host:<br/>"
                f"<code>python -m vaultsync_server.scripts.admin_reset --username {username}</code>"
            )
        elif isinstance(exc, AuthenticationError):
            self._show_error("Invalid username or account password.")
        elif isinstance(exc, RateLimitError):
            self._show_error(f"Rate limit exceeded: {exc}")
        else:
            self._show_error(f"Login failed: {exc}")

    def _on_login_finally(self) -> None:
        self.login_btn.setEnabled(True)
        self.login_btn.setText("Log In with Account Password")

    def _on_unlock_clicked(self) -> None:
        master_pwd = self.master_pwd_input.text()
        if not master_pwd:
            self._show_error("Please enter your vault master password.")
            return

        self.unlock_btn.setEnabled(False)
        self.unlock_btn.setText("Unwrapping Key & Decrypting...")
        self.status_banner.hide()

        run_async(
            self.session.unlock_vault(master_pwd),
            on_success=lambda _: self.login_unlocked_success.emit(),
            on_error=self._handle_unlock_error,
            on_finally=self._on_unlock_finally,
        )

    def _handle_unlock_error(self, exc: Exception) -> None:
        if isinstance(exc, DecryptionFailedError):
            self._show_error(
                "<b>Incorrect Vault Master Password:</b> Authentication tag verification failed. "
                "The vault remains locked."
            )
        else:
            self._show_error(f"Failed to unlock vault: {exc}")

    def _on_unlock_finally(self) -> None:
        self.unlock_btn.setEnabled(True)
        self.unlock_btn.setText("Unlock Vault")

    def _on_logout_clicked(self) -> None:
        run_async(self.session.logout(), on_finally=self.reset_to_login)

    def _show_error(self, message: str) -> None:
        self.status_banner.setText(message)
        self.status_banner.setStyleSheet(
            "background-color: #3D1C1D; border: 1px solid #E01B24; border-radius: 6px; padding: 10px; color: #FFB3B6;"
        )
        self.status_banner.show()

    def _show_warning(self, message: str) -> None:
        self.status_banner.setText(message)
        self.status_banner.setStyleSheet(
            "background-color: #382A15; border: 1px solid #E5A50A; border-radius: 6px; padding: 10px; color: #FFDE8A;"
        )
        self.status_banner.show()
