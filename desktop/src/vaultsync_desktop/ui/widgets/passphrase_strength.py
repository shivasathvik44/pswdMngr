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

        self.advice_label = QLabel()
        self.advice_label.setWordWrap(True)
        self.advice_label.setProperty("class", "caption")
        self.advice_label.setStyleSheet("color: #A0A0B0; font-size: 11px;")

        layout.addWidget(self.bar)
        layout.addWidget(self.label)
        layout.addWidget(self.advice_label)

    def update_strength(self, passphrase: str) -> None:
        """Recalculate score and update visual indicator."""
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
        self.label.setText(f"Strength: <b>{label}</b> ({score}/100)")
        self.label.setStyleSheet(f"color: {color}; font-size: 11px;")

        if recs:
            self.advice_label.setText(" • " + "\n • ".join(recs))
            self.advice_label.show()
        else:
            self.advice_label.setText(
                "✓ Strong passphrase. Bounded against offline dictionary guessing via Argon2id."
            )
            self.advice_label.show()
