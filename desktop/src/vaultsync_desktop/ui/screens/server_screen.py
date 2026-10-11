"""Server connection screen."""

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
from vaultsync_desktop.models import ServerConnectionConfig


class ServerScreen(QWidget):
    """Screen for connecting to local development server or validating remote HTTPS host."""

    proceed_login = Signal()
    proceed_register = Signal()

    def __init__(self, session: VaultSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)

        card = QFrame()
        card.setProperty("class", "card")
        card.setFixedWidth(520)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(16)

        # Title
        title = QLabel("VaultSync")
        title.setProperty("class", "heading")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Self-Hosted, End-to-End Encrypted Password Manager")
        subtitle.setProperty("class", "subheading")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(10)

        # URL field
        url_label = QLabel("Sync Server URL:")
        self.url_input = QLineEdit()
        self.url_input.setText(self.session.config.server_url)
        self.url_input.setPlaceholderText("http://127.0.0.1:8000")

        card_layout.addWidget(url_label)
        card_layout.addWidget(self.url_input)

        # Notice
        notice = QLabel(
            "Security Policy: Plain HTTP is permitted strictly on loopback (127.0.0.1). "
            "Remote servers require authenticated HTTPS."
        )
        notice.setProperty("class", "caption")
        notice.setWordWrap(True)
        card_layout.addWidget(notice)

        # Status / Error banner
        self.status_banner = QLabel()
        self.status_banner.setWordWrap(True)
        self.status_banner.hide()
        card_layout.addWidget(self.status_banner)

        # Connect button
        self.connect_btn = QPushButton("Connect to Server")
        self.connect_btn.setProperty("class", "primary")
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        card_layout.addWidget(self.connect_btn)

        # Action buttons (hidden until connected)
        self.action_layout = QHBoxLayout()
        self.login_btn = QPushButton("Log In to Account")
        self.login_btn.setProperty("class", "primary")
        self.login_btn.clicked.connect(self.proceed_login.emit)

        self.register_btn = QPushButton("Create New Account")
        self.register_btn.setProperty("class", "secondary")
        self.register_btn.clicked.connect(self.proceed_register.emit)

        self.action_layout.addWidget(self.login_btn)
        self.action_layout.addWidget(self.register_btn)

        self.action_container = QWidget()
        self.action_container.setLayout(self.action_layout)
        self.action_container.hide()
        card_layout.addWidget(self.action_container)

        layout.addWidget(card)

    def _on_connect_clicked(self) -> None:
        url = self.url_input.text().strip()
        config = ServerConnectionConfig(server_url=url)
        valid, err_msg = config.validate_url()
        if not valid:
            self._show_error(err_msg)
            return

        self.connect_btn.setEnabled(False)
        self.connect_btn.setText("Connecting...")
        self.status_banner.hide()

        # Update API client base URL
        self.session.config.server_url = url
        self.session.config.save()
        self.session.api.base_url = url.rstrip("/")

        # Run health check asynchronously via threadsafe bridge
        run_async(
            self.session.api.check_health(),
            on_success=self._on_health_success,
            on_error=lambda exc: self._show_error(f"Connection failed: {exc}"),
            on_finally=self._on_health_finally,
        )

    def _on_health_success(self, res: dict) -> None:
        status = res.get("status", "unknown")
        version = res.get("version", "0.1.0")
        self._show_success(f"Connected successfully to VaultSync Server v{version} (status: {status}).")
        self.action_container.show()

    def _on_health_finally(self) -> None:
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("Connect to Server")

    def _show_error(self, message: str) -> None:
        self.status_banner.setText(message)
        self.status_banner.setProperty("class", "error-banner")
        self.status_banner.setStyleSheet(
            "background-color: #3D1C1D; border: 1px solid #E01B24; border-radius: 6px; padding: 10px; color: #FFB3B6;"
        )
        self.status_banner.show()

    def _show_success(self, message: str) -> None:
        self.status_banner.setText(message)
        self.status_banner.setProperty("class", "info-banner")
        self.status_banner.setStyleSheet(
            "background-color: #1A3626; border: 1px solid #2EC27E; border-radius: 6px; padding: 10px; color: #A6F0C6;"
        )
        self.status_banner.show()
