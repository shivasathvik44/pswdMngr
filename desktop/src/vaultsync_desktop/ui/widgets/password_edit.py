"""Custom QLineEdit with show/hide password toggle."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget


class PasswordEdit(QWidget):
    """Secure password input field with show/hide reveal toggle."""

    def __init__(self, placeholder: str = "Enter password", parent: QWidget | None = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self.line_edit = QLineEdit()
        self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_edit.setPlaceholderText(placeholder)

        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setToolTip("Show / Hide password")
        self.toggle_btn.setFixedWidth(36)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self._toggle_echo_mode)

        layout.addWidget(self.line_edit)
        layout.addWidget(self.toggle_btn)

        self._is_revealed = False

    def _toggle_echo_mode(self) -> None:
        self._is_revealed = not self._is_revealed
        if self._is_revealed:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("🔒")
        else:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("👁")

    def reset_reveal(self) -> None:
        """Reset visibility back to masked password mode."""
        self._is_revealed = False
        self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle_btn.setText("👁")

    def text(self) -> str:
        return self.line_edit.text()

    def setText(self, text: str) -> None:
        self.line_edit.setText(text)

    def clear(self) -> None:
        self.line_edit.clear()
        self.reset_reveal()

    def setFocus(self) -> None:
        self.line_edit.setFocus()

    def selectAll(self) -> None:
        self.line_edit.selectAll()

    def setEnabled(self, enabled: bool) -> None:
        super().setEnabled(enabled)
        self.line_edit.setEnabled(enabled)
        self.toggle_btn.setEnabled(enabled)

    @property
    def textChanged(self):
        return self.line_edit.textChanged

    @property
    def returnPressed(self):
        return self.line_edit.returnPressed

