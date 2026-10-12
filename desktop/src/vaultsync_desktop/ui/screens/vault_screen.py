"""Main password vault management screen."""

import asyncio
from typing import Optional
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from vaultsync_desktop.api_client import ConflictError
from vaultsync_desktop.async_bridge import run_async
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.ui.widgets.password_edit import PasswordEdit


class VaultScreen(QWidget):
    """Primary password manager interface with search, item editor, and clipboard integration."""

    request_lock = Signal()
    request_settings = Signal()

    def __init__(self, session: VaultSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self.current_item_id: Optional[str] = None
        self.session.add_lock_callback(self.clear_vault_ui)
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # --------------------------------------------------------------------
        # Left Pane: List & Search
        # --------------------------------------------------------------------
        left_pane = QFrame()
        left_pane.setProperty("class", "sidebar")
        left_pane.setMinimumWidth(280)
        left_pane.setMaximumWidth(420)
        left_layout = QVBoxLayout(left_pane)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(10)

        # Header with Add and Sync buttons
        top_btn_layout = QHBoxLayout()
        self.new_btn = QPushButton("+ New Item")
        self.new_btn.setProperty("class", "primary")
        self.new_btn.clicked.connect(self._on_new_item_clicked)

        self.sync_btn = QPushButton("🔄 Sync")
        self.sync_btn.setProperty("class", "secondary")
        self.sync_btn.setToolTip("Synchronize records with server")
        self.sync_btn.clicked.connect(self._on_sync_clicked)

        top_btn_layout.addWidget(self.new_btn)
        top_btn_layout.addWidget(self.sync_btn)
        left_layout.addLayout(top_btn_layout)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search vault items...")
        self.search_input.textChanged.connect(self._on_search_changed)
        left_layout.addWidget(self.search_input)

        # Item List
        self.item_list = QListWidget()
        self.item_list.itemSelectionChanged.connect(self._on_item_selection_changed)
        left_layout.addWidget(self.item_list)

        # Status badge at bottom of sidebar
        self.sync_status_label = QLabel("Synced")
        self.sync_status_label.setProperty("class", "caption")
        self.sync_status_label.setStyleSheet("color: #2EC27E; font-size: 11px;")
        left_layout.addWidget(self.sync_status_label)

        splitter.addWidget(left_pane)

        # --------------------------------------------------------------------
        # Right Pane: Item Detail & Editor
        # --------------------------------------------------------------------
        self.right_pane = QFrame()
        self.right_pane.setProperty("class", "card")
        self.right_layout = QVBoxLayout(self.right_pane)
        self.right_layout.setContentsMargins(20, 20, 20, 20)
        self.right_layout.setSpacing(12)

        # Empty State Placeholder
        self.placeholder_widget = QWidget()
        ph_layout = QVBoxLayout(self.placeholder_widget)
        ph_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_label = QLabel("Select an entry to view or click '+ New Item' to create one.")
        ph_label.setStyleSheet("color: #7A7A8E; font-size: 14px;")
        ph_layout.addWidget(ph_label)
        self.right_layout.addWidget(self.placeholder_widget)

        # Editor Form Container
        self.editor_widget = QWidget()
        editor_layout = QVBoxLayout(self.editor_widget)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(10)

        # Banner for feedback / errors / clipboard
        self.banner_label = QLabel()
        self.banner_label.setWordWrap(True)
        self.banner_label.hide()
        editor_layout.addWidget(self.banner_label)

        # Title
        editor_layout.addWidget(QLabel("Title:"))
        self.title_input = QLineEdit()
        editor_layout.addWidget(self.title_input)

        # Username + Copy
        user_row = QHBoxLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username or email")
        self.copy_user_btn = QPushButton("Copy")
        self.copy_user_btn.setFixedWidth(64)
        self.copy_user_btn.clicked.connect(lambda: self._copy_to_clipboard(self.username_input.text(), "Username"))
        user_row.addWidget(self.username_input)
        user_row.addWidget(self.copy_user_btn)
        editor_layout.addWidget(QLabel("Username:"))
        editor_layout.addLayout(user_row)

        # Password + Copy
        pwd_row = QHBoxLayout()
        self.password_input = PasswordEdit(placeholder="Password")
        self.copy_pwd_btn = QPushButton("Copy")
        self.copy_pwd_btn.setFixedWidth(64)
        self.copy_pwd_btn.clicked.connect(lambda: self._copy_to_clipboard(self.password_input.text(), "Password"))
        pwd_row.addWidget(self.password_input)
        pwd_row.addWidget(self.copy_pwd_btn)
        editor_layout.addWidget(QLabel("Password:"))
        editor_layout.addLayout(pwd_row)

        # Website URL + Copy
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.copy_url_btn = QPushButton("Copy")
        self.copy_url_btn.setFixedWidth(64)
        self.copy_url_btn.clicked.connect(lambda: self._copy_to_clipboard(self.url_input.text(), "URL"))
        url_row.addWidget(self.url_input)
        url_row.addWidget(self.copy_url_btn)
        editor_layout.addWidget(QLabel("Website URL:"))
        editor_layout.addLayout(url_row)

        # Notes
        editor_layout.addWidget(QLabel("Notes:"))
        self.notes_input = QPlainTextEdit()
        self.notes_input.setPlaceholderText("Additional secure notes...")
        self.notes_input.setMaximumHeight(140)
        editor_layout.addWidget(self.notes_input)

        # Metadata
        self.meta_label = QLabel()
        self.meta_label.setProperty("class", "caption")
        editor_layout.addWidget(self.meta_label)

        # Form Buttons
        action_row = QHBoxLayout()
        self.save_btn = QPushButton("Save Entry")
        self.save_btn.setProperty("class", "primary")
        self.save_btn.clicked.connect(self._on_save_clicked)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setProperty("class", "danger")
        self.delete_btn.clicked.connect(self._on_delete_clicked)

        action_row.addWidget(self.save_btn)
        action_row.addWidget(self.delete_btn)
        action_row.addStretch()
        editor_layout.addLayout(action_row)

        self.right_layout.addWidget(self.editor_widget)
        self.editor_widget.hide()

        splitter.addWidget(self.right_pane)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        main_layout.addWidget(splitter)

    # ------------------------------------------------------------------------
    # Data Loading & List Management
    # ------------------------------------------------------------------------

    def reload_items(self) -> None:
        """Populate list from in-memory session items."""
        self.item_list.clear()
        query = self.search_input.text().strip().lower()

        for item_id, item in self.session.items.items():
            if item.is_deleted:
                continue
            if query and (query not in item.title.lower() and query not in item.username.lower() and query not in item.url.lower()):
                continue

            list_item = QListWidgetItem()
            display_title = item.title or "Untitled"
            display_user = f"  ({item.username})" if item.username else ""
            list_item.setText(f"{display_title}{display_user}")
            list_item.setData(Qt.ItemDataRole.UserRole, item_id)
            self.item_list.addItem(list_item)

        # Update sync badge
        count = len([i for i in self.session.items.values() if not i.is_deleted])
        self.sync_status_label.setText(f"✓ Synced ({count} items)")
        self.sync_status_label.setStyleSheet("color: #2EC27E; font-size: 11px;")

    def _on_search_changed(self, text: str) -> None:
        self.reload_items()

    def _on_item_selection_changed(self) -> None:
        selected = self.item_list.selectedItems()
        if not selected:
            self._show_placeholder()
            return

        item_id = selected[0].data(Qt.ItemDataRole.UserRole)
        item = self.session.items.get(item_id)
        if item:
            self._load_item_into_editor(item)

    def clear_vault_ui(self) -> None:
        """Immediately clear all sensitive decrypted fields, search queries, and lists upon vault lock."""
        self.current_item_id = None
        self.search_input.clear()
        self.item_list.clear()
        self.title_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.url_input.clear()
        self.notes_input.clear()
        self.meta_label.clear()
        self.banner_label.hide()
        self.editor_widget.hide()
        self.placeholder_widget.show()
        self.sync_status_label.setText("Locked")
        self.sync_status_label.setStyleSheet("color: #FFA3A6; font-size: 11px;")

    def _show_placeholder(self) -> None:
        self.current_item_id = None
        self.editor_widget.hide()
        self.placeholder_widget.show()
        self.banner_label.hide()

    def _load_item_into_editor(self, item: VaultItem) -> None:
        self.current_item_id = item.id
        self.title_input.setText(item.title)
        self.username_input.setText(item.username)
        self.password_input.setText(item.password)
        self.url_input.setText(item.url)
        self.notes_input.setPlainText(item.notes)
        self.meta_label.setText(f"Revision {item.revision} • Updated {item.updated_at[:19]}")

        self.delete_btn.show()
        self.banner_label.hide()
        self.placeholder_widget.hide()
        self.editor_widget.show()

    def _on_new_item_clicked(self) -> None:
        self.item_list.clearSelection()
        self.current_item_id = None
        self.title_input.setText("New Item")
        self.username_input.clear()
        self.password_input.clear()
        self.url_input.clear()
        self.notes_input.clear()
        self.meta_label.setText("New Record (unsaved)")

        self.delete_btn.hide()
        self.banner_label.hide()
        self.placeholder_widget.hide()
        self.editor_widget.show()
        self.title_input.setFocus()

    # ------------------------------------------------------------------------
    # Actions: Save, Delete, Sync
    # ------------------------------------------------------------------------

    def _on_save_clicked(self) -> None:
        title = self.title_input.text().strip()
        if not title:
            self._show_banner("Title cannot be empty.", is_error=True)
            return

        item_id = self.current_item_id
        existing = self.session.items.get(item_id) if item_id else None

        item = VaultItem(
            id=item_id or VaultItem().id,
            title=title,
            username=self.username_input.text().strip(),
            password=self.password_input.text(),
            url=self.url_input.text().strip(),
            notes=self.notes_input.toPlainText(),
            revision=existing.revision if existing else 1,
        )

        self.save_btn.setEnabled(False)
        self.save_btn.setText("Encrypting & Saving...")

        run_async(
            self.session.save_item(item),
            on_success=self._on_save_success,
            on_error=self._on_save_error,
            on_finally=lambda: (self.save_btn.setEnabled(True), self.save_btn.setText("Save Entry")),
        )

    def _on_save_success(self, saved: VaultItem) -> None:
        if not self.session.is_unlocked:
            return
        self._show_banner("✓ Entry encrypted and saved successfully.", is_error=False)
        self.reload_items()
        self._load_item_into_editor(saved)

    def _on_save_error(self, exc: Exception) -> None:
        if not self.session.is_unlocked:
            return
        if isinstance(exc, ConflictError):
            self._show_banner(
                "<b>Conflict Detected:</b> This item was modified on another device (revision mismatch). "
                "Please click '🔄 Sync' to review the current version.",
                is_error=True,
            )
        else:
            self._show_banner(f"Failed to save item: {exc}", is_error=True)

    def _on_delete_clicked(self) -> None:
        if not self.current_item_id or not self.session.is_unlocked:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            "Are you sure you want to delete this vault item? A tombstone will propagate to all devices.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.delete_btn.setEnabled(False)
            item_id = self.current_item_id
            run_async(
                self.session.delete_item(item_id),
                on_success=lambda _: (self.reload_items(), self._show_placeholder()) if self.session.is_unlocked else None,
                on_error=lambda exc: self._show_banner(f"Failed to delete item: {exc}", is_error=True) if self.session.is_unlocked else None,
                on_finally=lambda: self.delete_btn.setEnabled(True),
            )

    def _on_sync_clicked(self) -> None:
        if not self.session.is_unlocked:
            return
        self.sync_btn.setEnabled(False)
        self.sync_status_label.setText("Syncing...")
        self.sync_status_label.setStyleSheet("color: #E5A50A; font-size: 11px;")

        run_async(
            self.session.sync_records(),
            on_success=lambda _: self.reload_items() if self.session.is_unlocked else None,
            on_error=lambda _: (
                self.sync_status_label.setText("Sync failed"),
                self.sync_status_label.setStyleSheet("color: #E01B24; font-size: 11px;"),
            ) if self.session.is_unlocked else None,
            on_finally=lambda: self.sync_btn.setEnabled(True),
        )

    # ------------------------------------------------------------------------
    # Secure Clipboard Handling
    # ------------------------------------------------------------------------

    def _copy_to_clipboard(self, text: str, field_name: str) -> None:
        if not text:
            return

        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        clear_seconds = self.session.config.clipboard_clear_seconds

        self._show_banner(
            f"📋 {field_name} copied to clipboard (will automatically clear in {clear_seconds}s).",
            is_error=False,
        )

        # Schedule clearing timer that ONLY clears if clipboard still holds the copied value
        def clear_if_matches():
            current_clip = QApplication.clipboard().text()
            if current_clip == text:
                QApplication.clipboard().clear()
                self._show_banner("🔒 Clipboard cleared for security.", is_error=False)

        QTimer.singleShot(clear_seconds * 1000, clear_if_matches)

    def _show_banner(self, message: str, is_error: bool = False) -> None:
        self.banner_label.setText(message)
        if is_error:
            self.banner_label.setStyleSheet(
                "background-color: #3D1C1D; border: 1px solid #E01B24; border-radius: 6px; padding: 10px; color: #FFB3B6;"
            )
        else:
            self.banner_label.setStyleSheet(
                "background-color: #1A3626; border: 1px solid #2EC27E; border-radius: 6px; padding: 10px; color: #A6F0C6;"
            )
        self.banner_label.show()
