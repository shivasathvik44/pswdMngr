"""Passphrase strength indicator and entropy guidance widget."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget

from vaultsync_desktop.crypto import evaluate_passphrase_strength


class PassphraseStrengthWidget(QWidget):
    """Visual guidance displaying passphrase entropy and offline-attack resistance."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(4)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)

        self.label = QLabel("Strength: Not evaluated")
        self.label.setProperty("class", "caption")
        self.label.setTextFormat(Qt.TextFormat.RichText)

        self.advice_label = QLabel()
        self.advice_label.setWordWrap(True)
        self.advice_label.setProperty("class", "caption")
        self.advice_label.setStyleSheet("color: #A0A0B0; font-size: 11px;")
        self.advice_label.hide()

        layout.addWidget(self.bar)
        layout.addWidget(self.label)
        layout.addWidget(self.advice_label)

    def reset(self) -> None:
        """Reset indicator to initial unevaluated state."""
        self.bar.setValue(0)
        self.bar.setStyleSheet("")
        self.label.setText("Strength: Not evaluated")
        self.label.setStyleSheet("")
        self.advice_label.clear()
        self.advice_label.hide()

    def update_strength(self, passphrase: str) -> None:
        """Recalculate score and update visual indicator."""
        if not passphrase:
            self.reset()
            return

        score, label, recs = evaluate_passphrase_strength(passphrase)
        self.bar.setValue(score)

        if score < 40:
            color = "#E01B24"  # Red
        elif score < 70:
            color = "#E5A50A"  # Amber
        elif score < 90:
            color = "#3584E4"  # Blue
        else:
            color = "#2EC27E"  # Green

        self.bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}"
        )
        self.label.setText(f"Strength: <b>{label}</b> ({score}/100) [Heuristic Guidance]")
        self.label.setStyleSheet(f"color: {color}; font-size: 11px;")

        if recs:
            self.advice_label.setText(" • " + "\n • ".join(recs))
            self.advice_label.show()
        else:
            self.advice_label.setText(
                "✓ High heuristic score. Note: True offline cracking resistance requires "
                "random word selection (e.g. 5+ Diceware words yielding ≥64 bits true entropy)."
            )
            self.advice_label.show()
