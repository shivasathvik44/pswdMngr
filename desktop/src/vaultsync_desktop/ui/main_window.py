"""Main application window coordinating desktop screens and auto-lock."""

import asyncio
from typing import Optional
from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from vaultsync_desktop.async_bridge import run_async
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.ui.screens.login_screen import LoginScreen
from vaultsync_desktop.ui.screens.register_screen import RegisterScreen
from vaultsync_desktop.ui.screens.server_screen import ServerScreen
from vaultsync_desktop.ui.screens.settings_screen import SettingsScreen
from vaultsync_desktop.ui.screens.vault_screen import VaultScreen
from vaultsync_desktop.ui.theme import DARK_THEME_QSS


class ActivityFilter(QObject):
    """Global event filter monitoring user interactions for inactivity auto-lock."""

    def __init__(self, session: VaultSession, parent: QObject | None = None):
        super().__init__(parent)
        self.session = session

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in (
            QEvent.Type.MouseMove,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.KeyPress,
            QEvent.Type.Wheel,
        ):
            self.session.register_activity()
        return super().eventFilter(watched, event)


class MainWindow(QMainWindow):
    """Main desktop application window."""

    SCREEN_SERVER = 0
    SCREEN_REGISTER = 1
    SCREEN_LOGIN = 2
    SCREEN_VAULT = 3
    SCREEN_SETTINGS = 4

    def __init__(self, session: Optional[VaultSession] = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session or VaultSession()
        self.setWindowTitle("VaultSync — End-to-End Encrypted Password Manager")
        self.resize(1024, 680)
        self.setMinimumSize(800, 540)
        self.setStyleSheet(DARK_THEME_QSS)

        # Wire auto-lock callback
        self.session.add_lock_callback(self._on_vault_locked)

        # Activity monitoring
        self.activity_filter = ActivityFilter(self.session, self)
        QApplication.instance().installEventFilter(self.activity_filter)

        # Periodic auto-lock check timer (checks every 5 seconds)
        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.setInterval(5000)
        self.auto_lock_timer.timeout.connect(self.session.check_inactivity)
        self.auto_lock_timer.start()

        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top App Header
        header = QWidget()
        header.setStyleSheet("background-color: #1F1F26; border-bottom: 1px solid #2B2B36;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 10, 16, 10)

        app_title = QLabel("🛡️ VaultSync")
        app_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        header_layout.addWidget(app_title)

        header_layout.addStretch()

        # Status Badges
        self.lock_badge = QLabel("🔒 Locked")
        self.lock_badge.setStyleSheet(
            "background-color: #3D2224; color: #FFA3A6; border: 1px solid #9C141E; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; font-weight: 600;"
        )
        header_layout.addWidget(self.lock_badge)

        self.quick_lock_btn = QPushButton("Lock Vault")
        self.quick_lock_btn.setProperty("class", "secondary")
        self.quick_lock_btn.setFixedWidth(84)
        self.quick_lock_btn.clicked.connect(self.session.lock)
        self.quick_lock_btn.hide()
        header_layout.addWidget(self.quick_lock_btn)

        self.settings_btn = QPushButton("⚙️ Settings")
        self.settings_btn.setProperty("class", "secondary")
        self.settings_btn.setFixedWidth(94)
        self.settings_btn.clicked.connect(self._goto_settings)
        self.settings_btn.hide()
        header_layout.addWidget(self.settings_btn)

        main_layout.addWidget(header)

        # Screen Stack
        self.stack = QStackedWidget()

        # 0: Server Screen
        self.server_screen = ServerScreen(self.session)
        self.server_screen.proceed_login.connect(self._goto_login)
        self.server_screen.proceed_register.connect(self._goto_register)
        self.stack.addWidget(self.server_screen)

        # 1: Register Screen
        self.register_screen = RegisterScreen(self.session)
        self.register_screen.registered_success.connect(self._on_unlocked_and_ready)
        self.register_screen.switch_to_login.connect(self._goto_login)
        self.stack.addWidget(self.register_screen)

        # 2: Login Screen
        self.login_screen = LoginScreen(self.session)
        self.login_screen.login_unlocked_success.connect(self._on_unlocked_and_ready)
        self.login_screen.switch_to_register.connect(self._goto_register)
        self.login_screen.switch_to_server.connect(self._goto_server)
        self.stack.addWidget(self.login_screen)

        # 3: Vault Screen
        self.vault_screen = VaultScreen(self.session)
        self.stack.addWidget(self.vault_screen)

        # 4: Settings Screen
        self.settings_screen = SettingsScreen(self.session)
        self.settings_screen.back_to_vault.connect(self._goto_vault)
        self.settings_screen.request_lock.connect(self.session.lock)
        self.settings_screen.request_logout.connect(self._on_request_logout)
        self.stack.addWidget(self.settings_screen)

        main_layout.addWidget(self.stack)

        # Start on Server Screen
        self.stack.setCurrentIndex(self.SCREEN_SERVER)

    # ------------------------------------------------------------------------
    # Navigation Methods
    # ------------------------------------------------------------------------

    def _goto_server(self) -> None:
        self.stack.setCurrentIndex(self.SCREEN_SERVER)
        self._update_header_state()

    def _goto_register(self) -> None:
        self.stack.setCurrentIndex(self.SCREEN_REGISTER)
        self._update_header_state()

    def _goto_login(self) -> None:
        self.login_screen.reset_to_login()
        self.stack.setCurrentIndex(self.SCREEN_LOGIN)
        self._update_header_state()

    def _goto_vault(self) -> None:
        if self.session.is_unlocked:
            self.vault_screen.reload_items()
            self.stack.setCurrentIndex(self.SCREEN_VAULT)
            self._update_header_state()
        else:
            self._goto_login()

    def _goto_settings(self) -> None:
        if self.session.is_unlocked:
            self.stack.setCurrentIndex(self.SCREEN_SETTINGS)
            self._update_header_state()

    def _on_unlocked_and_ready(self) -> None:
        """Invoked when user successfully registers or logs in + unlocks vault."""
        self._goto_vault()

    def _on_vault_locked(self) -> None:
        """Invoked on manual lock or auto-lock timeout."""
        self._update_header_state()
        if self.session.is_authenticated:
            self.login_screen.show_unlock_prompt(self.session.username)
        else:
            self.login_screen.reset_to_login()
        self.stack.setCurrentIndex(self.SCREEN_LOGIN)

    def _on_request_logout(self) -> None:
        run_async(self.session.logout(), on_finally=self._goto_login)

    def _update_header_state(self) -> None:
        if self.session.is_unlocked:
            self.lock_badge.setText("🔓 Unlocked")
            self.lock_badge.setStyleSheet(
                "background-color: #173623; color: #8DF0B5; border: 1px solid #2EC27E; "
                "border-radius: 4px; padding: 4px 8px; font-size: 11px; font-weight: 600;"
            )
            self.quick_lock_btn.show()
            self.settings_btn.show()
        else:
            self.lock_badge.setText("🔒 Locked")
            self.lock_badge.setStyleSheet(
                "background-color: #3D2224; color: #FFA3A6; border: 1px solid #9C141E; "
                "border-radius: 4px; padding: 4px 8px; font-size: 11px; font-weight: 600;"
            )
            self.quick_lock_btn.hide()
            self.settings_btn.hide()
