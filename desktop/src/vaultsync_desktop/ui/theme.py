"""VaultSync Desktop UI theme and styling.

A restrained, accessible dark theme conforming to Linux desktop conventions
(GNOME / Adwaita Dark / Wayland / Hyprland compatible).
"""

DARK_THEME_QSS = """
/* Global Application Styles */
QWidget {
    background-color: #1E1E24;
    color: #E6E6E6;
    font-family: 'Cantarell', 'Inter', 'Segoe UI', sans-serif;
    font-size: 13px;
    selection-background-color: #3584E4;
    selection-color: #FFFFFF;
}

/* Window & Container Backgrounds */
QMainWindow, QDialog {
    background-color: #18181D;
}

QFrame.card {
    background-color: #26262F;
    border: 1px solid #363642;
    border-radius: 8px;
    padding: 16px;
}

QFrame.sidebar {
    background-color: #1F1F27;
    border-right: 1px solid #33333F;
}

/* Headings and Labels */
QLabel.heading {
    font-size: 20px;
    font-weight: 700;
    color: #FFFFFF;
}

QLabel.subheading {
    font-size: 14px;
    font-weight: 600;
    color: #A0A0B0;
}

QLabel.caption {
    font-size: 11px;
    color: #8C8C9E;
}

QLabel.info-banner {
    background-color: #1E2D4A;
    border: 1px solid #3584E4;
    border-radius: 6px;
    padding: 10px;
    color: #BDDCFF;
    font-size: 12px;
}

QLabel.warning-banner {
    background-color: #382A15;
    border: 1px solid #E5A50A;
    border-radius: 6px;
    padding: 10px;
    color: #FFDE8A;
    font-size: 12px;
}

QLabel.error-banner {
    background-color: #3D1C1D;
    border: 1px solid #E01B24;
    border-radius: 6px;
    padding: 10px;
    color: #FFB3B6;
    font-size: 12px;
}

/* Buttons */
QPushButton {
    background-color: #333340;
    color: #FFFFFF;
    border: 1px solid #454556;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #404052;
    border-color: #55556A;
}

QPushButton:pressed {
    background-color: #2B2B38;
}

QPushButton:disabled {
    background-color: #24242D;
    color: #6A6A7A;
    border-color: #30303C;
}

QPushButton.primary {
    background-color: #3584E4;
    border: 1px solid #4B96F0;
    color: #FFFFFF;
}

QPushButton.primary:hover {
    background-color: #4992EE;
}

QPushButton.primary:pressed {
    background-color: #226BC4;
}

QPushButton.danger {
    background-color: #C01C28;
    border: 1px solid #D62D38;
    color: #FFFFFF;
}

QPushButton.danger:hover {
    background-color: #D62D38;
}

QPushButton.danger:pressed {
    background-color: #9C141E;
}

QPushButton.secondary {
    background-color: transparent;
    border: 1px solid #454556;
}

QPushButton.secondary:hover {
    background-color: #2C2C38;
}

/* Text Inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: #16161B;
    border: 1px solid #3B3B4A;
    border-radius: 6px;
    padding: 8px 12px;
    color: #FFFFFF;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #3584E4;
}

QLineEdit:disabled, QTextEdit:disabled {
    background-color: #121215;
    color: #666675;
    border-color: #282833;
}

/* ComboBox */
QComboBox {
    padding-right: 24px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left-width: 0px;
}

QComboBox QAbstractItemView {
    background-color: #22222B;
    border: 1px solid #3B3B4A;
    selection-background-color: #3584E4;
    color: #FFFFFF;
}

/* List Views */
QListWidget {
    background-color: #1A1A21;
    border: 1px solid #30303D;
    border-radius: 6px;
    outline: none;
}

QListWidget::item {
    padding: 10px 12px;
    border-bottom: 1px solid #252530;
    border-radius: 4px;
    margin: 2px 4px;
}

QListWidget::item:hover {
    background-color: #282834;
}

QListWidget::item:selected {
    background-color: #3584E4;
    color: #FFFFFF;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background-color: #18181D;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #3E3E4E;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #55556A;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Progress Bar */
QProgressBar {
    border: 1px solid #30303D;
    border-radius: 4px;
    text-align: center;
    background-color: #16161B;
    color: #FFFFFF;
    height: 8px;
}

QProgressBar::chunk {
    background-color: #3584E4;
    border-radius: 3px;
}
"""
