"""VaultSync Desktop secure token storage and configuration persistence.

Security Guarantees:
- Uses OS Secret Service / Keyring integration (GNOME Keyring on Fedora) for session bearer tokens.
- Never persists or caches the vault master password, KEK, or raw VEK.
- Provides a secure in-memory / encrypted fallback if the system Keyring daemon is unavailable.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

KEYRING_SERVICE_NAME = "vaultsync"
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "vaultsync"


class TokenStorage:
    """Manages persistent session tokens using OS Keyring with graceful fallback."""

    def __init__(self, service_name: str = KEYRING_SERVICE_NAME):
        self.service_name = service_name
        self._memory_fallback: dict[str, str] = {}
        self._keyring_available: Optional[bool] = None

    def _check_keyring(self) -> bool:
        if self._keyring_available is not None:
            return self._keyring_available
        try:
            import keyring
            # Attempt a probe to verify backend functionality
            keyring.get_password(self.service_name, "__probe__")
            self._keyring_available = True
        except Exception as exc:
            logger.info("System keyring not accessible (%s). Using fallback session storage.", exc)
            self._keyring_available = False
        return self._keyring_available

    @property
    def is_using_fallback(self) -> bool:
        """True if system keyring is unavailable and volatile in-memory fallback is active."""
        return not self._check_keyring()

    def save_session_token(self, username: str, token: str) -> None:
        """Store session token in Keyring or fallback."""
        if self._check_keyring():
            try:
                import keyring
                keyring.set_password(self.service_name, username, token)
                return
            except Exception as exc:
                logger.warning("Failed to store token in keyring (%s); using in-memory store.", exc)

        self._memory_fallback[username] = token

    def get_session_token(self, username: str) -> Optional[str]:
        """Retrieve stored session token."""
        if self._check_keyring():
            try:
                import keyring
                tok = keyring.get_password(self.service_name, username)
                if tok is not None:
                    return tok
            except Exception as exc:
                logger.warning("Failed to read token from keyring (%s).", exc)

        return self._memory_fallback.get(username)

    def delete_session_token(self, username: str) -> None:
        """Delete stored session token upon logout."""
        if self._check_keyring():
            try:
                import keyring
                keyring.delete_password(self.service_name, username)
            except Exception:
                pass

        self._memory_fallback.pop(username, None)


class AppConfig:
    """Manages non-sensitive user preferences (e.g., server URL, auto-lock timeout).
    
    Passwords, keys, and tokens are NEVER stored in this configuration file.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config_dir = config_path.parent if config_path else DEFAULT_CONFIG_DIR
        self.config_file = config_path or (self.config_dir / "config.json")
        self.server_url: str = "http://127.0.0.1:8000"
        self.last_username: str = ""
        self.auto_lock_minutes: int = 15
        self.clipboard_clear_seconds: int = 30
        self.load()

    def load(self) -> None:
        """Load configuration from JSON file if it exists."""
        if not self.config_file.exists():
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.server_url = data.get("server_url", self.server_url)
                self.last_username = data.get("last_username", self.last_username)
                self.auto_lock_minutes = int(data.get("auto_lock_minutes", self.auto_lock_minutes))
                self.clipboard_clear_seconds = int(data.get("clipboard_clear_seconds", self.clipboard_clear_seconds))
        except Exception as exc:
            logger.warning("Failed to read config file (%s). Using defaults.", exc)

    def save(self) -> None:
        """Save configuration to JSON file."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.config_dir, 0o700)
            except Exception:
                pass
            data = {
                "server_url": self.server_url,
                "last_username": self.last_username,
                "auto_lock_minutes": self.auto_lock_minutes,
                "clipboard_clear_seconds": self.clipboard_clear_seconds,
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            try:
                os.chmod(self.config_file, 0o600)
            except Exception:
                pass
        except Exception as exc:
            logger.warning("Failed to save config file (%s).", exc)
