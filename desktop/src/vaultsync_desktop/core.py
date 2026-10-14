"""VaultSync Desktop core session and sync manager.

Coordinates authentication, client-side encryption/decryption,
in-memory item storage, auto-lock timeouts, and clipboard clearing.
"""

import logging
import time
from typing import Callable, Optional

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope
from vaultsync_server.crypto.errors import CryptoError
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey

from vaultsync_desktop.api_client import (
    ApiClient,
    ApiError,
    AuthenticationError,
    ConflictError,
    MigrationRequiredError,
    NotFoundError,
)
from vaultsync_desktop.crypto import (
    clear_key_material,
    create_initial_vault_key_and_envelope,
    rotate_master_password,
    unlock_vault_with_master_password,
)
from vaultsync_desktop.async_bridge import call_on_gui_thread
from vaultsync_desktop.models import VaultItem
from vaultsync_desktop.storage import AppConfig, TokenStorage

logger = logging.getLogger(__name__)


class VaultSession:
    """Central state manager for authentication, vault keys, items, and auto-lock."""

    def __init__(self, config: Optional[AppConfig] = None, storage: Optional[TokenStorage] = None):
        self.config = config or AppConfig()
        self.storage = storage or TokenStorage()
        self.api = ApiClient(base_url=self.config.server_url)

        # Account / Auth state
        self.username: str = ""
        self.account_id: str = ""
        self.session_token: Optional[str] = None
        self.kdf_salt: str = ""
        self.wrapped_vault_key: str = ""

        # Vault state (only populated when unlocked)
        self.is_unlocked: bool = False
        self.lock_generation: int = 0
        self._vault_key: Optional[VaultKey] = None
        self.items: dict[str, VaultItem] = {}
        self.sync_cursor: int = 0

        # Activity & auto-lock
        self.last_activity_time: float = time.time()
        self.on_lock_callbacks: list[Callable[[], None]] = []

    @property
    def is_authenticated(self) -> bool:
        """True if the client holds a valid session token on the server."""
        return bool(self.session_token and self.username)

    def register_activity(self) -> None:
        """Update last user interaction timestamp."""
        self.last_activity_time = time.time()

    def check_inactivity(self) -> bool:
        """Check if vault should auto-lock due to user inactivity."""
        if not self.is_unlocked:
            return False
        timeout_seconds = self.config.auto_lock_minutes * 60
        if timeout_seconds > 0 and (time.time() - self.last_activity_time >= timeout_seconds):
            logger.info("Auto-lock triggered after %d minutes of inactivity.", self.config.auto_lock_minutes)
            self.lock()
            return True
        return False

    def add_lock_callback(self, callback: Callable[[], None]) -> None:
        """Register callback invoked whenever vault locks."""
        self.on_lock_callbacks.append(callback)

    def remove_lock_callback(self, callback: Callable[[], None]) -> None:
        """Unregister callback invoked whenever vault locks."""
        if callback in self.on_lock_callbacks:
            self.on_lock_callbacks.remove(callback)

    def lock(self) -> None:
        """Securely lock the vault.
        
        Clears unwrapped VEK from memory, purges decrypted vault items,
        increments lock generation to invalidate in-flight async tasks,
        and triggers UI lock notifications on the Qt main GUI thread.
        """
        self.is_unlocked = False
        self.lock_generation += 1
        clear_key_material(self._vault_key)
        self._vault_key = None
        self.items.clear()
        self.sync_cursor = 0

        for cb in list(self.on_lock_callbacks):
            try:
                call_on_gui_thread(cb)
            except Exception as exc:
                logger.error("Error dispatching on_lock callback: %s", exc)

    async def logout(self) -> None:
        """Revoke session token on server and lock local vault."""
        try:
            if self.is_authenticated:
                await self.api.logout()
        except Exception as exc:
            logger.warning("Remote logout failed (%s); proceeding with local revocation.", exc)
        finally:
            if self.username:
                self.storage.delete_session_token(self.username)
            self.session_token = None
            self.username = ""
            self.account_id = ""
            self.kdf_salt = ""
            self.wrapped_vault_key = ""
            self.lock()

    # ------------------------------------------------------------------------
    # Registration, Login & Unlock
    # ------------------------------------------------------------------------

    async def register_account(
        self,
        username: str,
        account_password: str,
        vault_master_password: str,
    ) -> None:
        """Register a new account adhering strictly to Two-Credential architecture.

        Client generates the VEK locally, wraps it with vault_master_password,
        and sends only account_password and wrapped_vault_key to server.
        """
        vek, salt_b64, wrapped_env_json = create_initial_vault_key_and_envelope(vault_master_password)
        await self.api.register(
            username=username,
            account_password=account_password,
            kdf_salt=salt_b64,
            wrapped_vault_key=wrapped_env_json,
        )
        # Clean up temporary VEK
        clear_key_material(vek)

    async def login_account(
        self,
        username: str,
        account_password: str,
        device_name: str = "Fedora Desktop",
    ) -> dict[str, str]:
        """Authenticate with independent server account password.
        
        Does not unlock the vault. Returns dict with auth metadata.
        """
        data = await self.api.login(username=username, account_password=account_password, device_name=device_name)
        self.username = username
        self.account_id = data.get("account_id", "")
        self.session_token = data.get("session_token", "")
        self.kdf_salt = data.get("kdf_salt", "")
        self.wrapped_vault_key = data.get("wrapped_vault_key", "")

        # Persist session token in secure OS Keyring
        self.storage.save_session_token(username, self.session_token)
        self.config.last_username = username
        self.config.save()

        return {
            "username": self.username,
            "account_id": self.account_id,
            "has_vault_key": bool(self.wrapped_vault_key),
        }

    async def unlock_vault(self, vault_master_password: str) -> None:
        """Unlock the local vault using the user's master password.
        
        Derives KEK locally, verifies AES-GCM tag, loads VEK into memory,
        and performs initial record synchronization.
        """
        if not self.wrapped_vault_key:
            raise ApiError("No wrapped vault key found on server for this account.")

        try:
            vek = unlock_vault_with_master_password(self.wrapped_vault_key, vault_master_password)
        except Exception:
            # Safe failure: ensure vault remains locked and no remnants exist
            self.lock()
            raise

        self._vault_key = vek
        self.is_unlocked = True
        self.register_activity()

        # Perform initial sync
        await self.sync_records()

    # ------------------------------------------------------------------------
    # Record Synchronization & Mutation
    # ------------------------------------------------------------------------

    async def sync_records(self) -> None:
        """Fetch remote record changes and decrypt into local in-memory store.

        Supports pagination if the server has more items than the page limit.
        """
        if not self.is_unlocked or not self._vault_key:
            raise ApiError("Vault must be unlocked to synchronize records.")

        gen = self.lock_generation
        while True:
            try:
                sync_data = await self.api.fetch_sync(since_cursor=self.sync_cursor, limit=100)
            except AuthenticationError:
                self.lock()
                self.session_token = None
                if self.username:
                    self.storage.delete_session_token(self.username)
                raise

            if not self.is_unlocked or self.lock_generation != gen or not self._vault_key:
                logger.info("Sync aborted: vault locked while fetching updates.")
                return

            items = sync_data.get("items", [])
            next_cursor = sync_data.get("next_cursor", self.sync_cursor)
            has_more = sync_data.get("has_more", False)

            for rec in items:
                if not self.is_unlocked or self.lock_generation != gen or not self._vault_key:
                    logger.info("Sync iteration stopped: vault locked.")
                    return

                record_id = rec.get("record_id")
                if not record_id:
                    continue
                is_deleted = rec.get("is_deleted", False)
                revision = rec.get("revision", 1)

                if is_deleted:
                    self.items.pop(record_id, None)
                else:
                    ciphertext_payload = rec.get("ciphertext_payload", "")
                    if ciphertext_payload:
                        try:
                            env = EncryptedRecordEnvelope.from_json(ciphertext_payload)
                            if env.record_id != record_id:
                                logger.error("Envelope record_id %s mismatch with response %s", env.record_id, record_id)
                                continue
                            decrypted_bytes = decrypt_record(self._vault_key, env)
                            vault_item = VaultItem.from_secret_json(
                                record_id=record_id,
                                revision=revision,
                                secret_json=decrypted_bytes.decode("utf-8"),
                            )
                            self.items[record_id] = vault_item
                        except Exception as exc:
                            logger.error("Failed to decrypt record %s: %s", record_id, exc)

            if not self.is_unlocked or self.lock_generation != gen:
                return
            self.sync_cursor = next_cursor

            if not has_more or not items:
                break

    async def fetch_record(self, record_id: str) -> Optional[VaultItem]:
        """Fetch and decrypt an individual record by record_id from the server."""
        if not self.is_unlocked or not self._vault_key:
            raise ApiError("Vault must be unlocked to fetch records.")

        gen = self.lock_generation
        try:
            data = await self.api.get_record(record_id)
        except NotFoundError:
            self.items.pop(record_id, None)
            return None
        except AuthenticationError:
            self.lock()
            self.session_token = None
            if self.username:
                self.storage.delete_session_token(self.username)
            raise

        if not self.is_unlocked or self.lock_generation != gen or not self._vault_key:
            return None

        if data.get("is_deleted", False):
            self.items.pop(record_id, None)
            return None

        ciphertext_payload = data.get("ciphertext_payload", "")
        if ciphertext_payload:
            env = EncryptedRecordEnvelope.from_json(ciphertext_payload)
            if env.record_id != record_id:
                raise CryptoError(f"Envelope record_id mismatch: {env.record_id} != {record_id}")
            decrypted_bytes = decrypt_record(self._vault_key, env)
            vault_item = VaultItem.from_secret_json(
                record_id=record_id,
                revision=data.get("revision", 1),
                secret_json=decrypted_bytes.decode("utf-8"),
            )
            self.items[record_id] = vault_item
            return vault_item
        return None

    async def save_item(self, item: VaultItem) -> VaultItem:
        """Client-encrypt record contents and upload to backend."""
        if not self.is_unlocked or not self._vault_key:
            raise ApiError("Vault must be unlocked to save records.")

        self.register_activity()
        gen = self.lock_generation
        plaintext_json = item.to_secret_json()
        env = encrypt_record(self._vault_key, item.id, plaintext_json)
        ciphertext_json = env.to_json()

        is_new = item.id not in self.items
        try:
            if is_new:
                res = await self.api.create_record(record_id=item.id, ciphertext_payload=ciphertext_json)
                item.revision = res.get("revision", 1)
            else:
                res = await self.api.update_record(
                    record_id=item.id,
                    expected_revision=item.revision,
                    ciphertext_payload=ciphertext_json,
                )
                item.revision = res.get("revision", item.revision + 1)
            if "updated_at" in res:
                item.updated_at = str(res["updated_at"])
            if "created_at" in res and not item.created_at:
                item.created_at = str(res["created_at"])
        except AuthenticationError:
            self.lock()
            self.session_token = None
            if self.username:
                self.storage.delete_session_token(self.username)
            raise

        if not self.is_unlocked or self.lock_generation != gen:
            logger.info("Save discarded locally: vault locked while awaiting server response.")
            return item

        self.items[item.id] = item
        return item

    async def delete_item(self, item_id: str) -> None:
        """Tombstone record on backend and remove from local store."""
        if not self.is_unlocked:
            raise ApiError("Vault must be unlocked to delete records.")

        self.register_activity()
        gen = self.lock_generation
        item = self.items.get(item_id)
        if not item:
            return

        try:
            await self.api.delete_record(record_id=item_id, expected_revision=item.revision)
        except NotFoundError:
            logger.info("Record %s already deleted or not found on server.", item_id)
        except AuthenticationError:
            self.lock()
            self.session_token = None
            if self.username:
                self.storage.delete_session_token(self.username)
            raise

        if not self.is_unlocked or self.lock_generation != gen:
            return

        self.items.pop(item_id, None)

    # ------------------------------------------------------------------------
    # Settings & Credentials
    # ------------------------------------------------------------------------

    async def change_account_password(self, current_password: str, new_password: str) -> None:
        """Change server account password via PUT /api/v1/auth/password."""
        await self.api.change_account_password(current_password, new_password)

    async def rotate_vault_master_password(self, new_master_password: str) -> None:
        """Re-wrap existing VEK with new master password and update server.
        
        Preserves raw VEK so encrypted records do not need re-encryption.
        """
        if not self.is_unlocked or not self._vault_key:
            raise ApiError("Vault must be unlocked to rotate master password.")

        gen = self.lock_generation
        new_salt_b64, new_envelope_json = rotate_master_password(self._vault_key, new_master_password)
        try:
            await self.api.update_vault_key(wrapped_vault_key=new_envelope_json, kdf_salt=new_salt_b64)
        except AuthenticationError:
            self.lock()
            self.session_token = None
            if self.username:
                self.storage.delete_session_token(self.username)
            raise

        if not self.is_unlocked or self.lock_generation != gen:
            return

        self.kdf_salt = new_salt_b64
        self.wrapped_vault_key = new_envelope_json
