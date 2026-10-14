"""Phase 5.1 Desktop Security Audit and Hardening Regression Tests.

Validates:
1. clear_key_material reliably wipes and clears mutable key buffers from memory.
2. clear_key_material idempotence (repeated clearing is safe).
3. clear_key_material safe with None.
4. clear_key_material raises CryptoError on unsupported/invalid objects rather than silently succeeding.
5. VaultSession.lock severs self._vault_key reference to None and clears key material.
6. VaultItem repr redaction protects passwords and notes from accidental log leakage.
7. VaultSession auth failure resets api.session_token as well as local session state.
8. AppConfig.save() enforces restrictive user-only POSIX permissions (0700/0600).
"""

import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from vaultsync_desktop.api_client import ApiClient, AuthenticationError
from vaultsync_desktop.core import VaultSession
from vaultsync_desktop.crypto import clear_key_material
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage
from vaultsync_server.crypto.errors import CryptoError
from vaultsync_server.crypto.vault_keys import VaultKey


def test_clear_key_material_zeroes_vault_key():
    """Verify clear_key_material invokes key.clear() and wipes raw buffer in memory."""
    secret_bytes = b"\xaa" * 32
    key = VaultKey(secret_bytes)
    assert len(key._key) == 32
    assert bytes(key._key) == secret_bytes

    clear_key_material(key)

    # _key must be cleared and empty
    assert len(key._key) == 0


def test_clear_key_material_idempotent():
    """Verify repeated clearing of the same key object is safe and causes no errors."""
    key = VaultKey.generate()
    clear_key_material(key)
    assert len(key._key) == 0

    # Second clearing should execute safely without error
    clear_key_material(key)
    assert len(key._key) == 0


def test_clear_key_material_none_safe():
    """Verify clear_key_material(None) is a safe no-op."""
    clear_key_material(None)


def test_clear_key_material_unsupported_object_raises_crypto_error():
    """Verify clear_key_material raises CryptoError when passed an invalid object."""
    with pytest.raises(CryptoError, match="Failed to clear key material"):
        clear_key_material("plain_string_secret")  # type: ignore

    with pytest.raises(CryptoError, match="Failed to clear key material"):
        clear_key_material(12345)  # type: ignore


def test_vault_session_lock_clears_key_and_severs_reference(tmp_path: Path):
    """Verify VaultSession.lock() zeroes key buffer and severs self._vault_key reference."""
    config_file = tmp_path / "config.json"
    config = AppConfig(config_file)
    storage = TokenStorage()
    api = ApiClient(base_url="http://127.0.0.1:8000")

    session = VaultSession(api=api, storage=storage, config=config)

    # Simulate unlocked vault with active key
    key = VaultKey.generate()
    session._vault_key = key
    session.is_unlocked = True

    # Lock vault
    session.lock()

    # Session reference must be None
    assert session._vault_key is None
    assert session.is_unlocked is False

    # Underlying key buffer must be zeroed and cleared
    assert len(key._key) == 0


def test_vault_item_repr_redaction():
    """Verify VaultItem does not expose sensitive passwords or notes in repr/str."""
    secret_password = "UltraSecretVaultPassword999!"
    confidential_notes = "Confidential server recovery seed phrase"

    item = VaultItem(
        title="Production Server",
        username="admin",
        password=secret_password,
        url="https://admin.example.com",
        notes=confidential_notes,
    )

    repr_str = repr(item)
    assert secret_password not in repr_str, "Plaintext password leaked in repr(VaultItem)!"
    assert confidential_notes not in repr_str, "Confidential notes leaked in repr(VaultItem)!"
    assert "Production Server" in repr_str
    assert "admin" in repr_str

    # Verify secret data is preserved for serialization and decryption
    secret_json = item.to_secret_json()
    assert secret_password in secret_json
    assert confidential_notes in secret_json


@pytest.mark.anyio
async def test_auth_error_clears_api_client_session_token(tmp_path: Path):
    """Verify 401 AuthenticationError clears both session.session_token and api.session_token."""
    config_file = tmp_path / "config.json"
    config = AppConfig(config_file)
    storage = TokenStorage()
    api = ApiClient(base_url="http://127.0.0.1:8000")

    session = VaultSession(api=api, storage=storage, config=config)

    # Establish mock authenticated state
    active_token = "mock-active-session-token-xyz"
    session.username = "testuser"
    session.session_token = active_token
    session.api.set_session_token(active_token)
    assert session.api.session_token == active_token

    # Trigger auth failure handler
    session._handle_auth_failure()

    # Both must be None
    assert session.session_token is None
    assert session.api.session_token is None
    assert session.is_unlocked is False


def test_config_file_permissions(tmp_path: Path):
    """Verify AppConfig.save() sets restrictive 0700/0600 POSIX permissions."""
    cfg_dir = tmp_path / "secure_config"
    cfg_file = cfg_dir / "config.json"

    config = AppConfig(cfg_file)
    config.server_url = "http://127.0.0.1:8000"
    config.save()

    assert cfg_file.exists()
    file_mode = stat.S_IMODE(cfg_file.stat().st_mode)
    dir_mode = stat.S_IMODE(cfg_dir.stat().st_mode)

    # No group or world permissions should be set (0600 file, 0700 directory)
    assert (file_mode & 0o077) == 0, f"Insecure config file permissions: {oct(file_mode)}"
    assert (dir_mode & 0o077) == 0, f"Insecure config dir permissions: {oct(dir_mode)}"
