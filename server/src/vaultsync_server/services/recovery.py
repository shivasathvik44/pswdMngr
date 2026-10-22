"""Account recovery and administrative reset service.

Adheres strictly to the Two-Credential security model:
Account password reset allows an administrative or recovery process to establish
a new server login credential.
Crucially:
- It NEVER decrypts or modifies the vault contents or wrapped vault key.
- If the vault master password is lost, the encrypted records remain inaccessible.
- Server password reset does NOT restore access to the vault without the master password.
"""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.db.models import Account, Session
from vaultsync_server.services.auth import hash_password


class AccountNotFoundError(Exception):
    """Raised when an account cannot be located for recovery."""


def reset_account_password_admin(
    db: DbSession,
    username: str,
    new_account_password: str,
) -> Account:
    """Administratively reset an account password without touching encrypted vault data.
    
    This is also used to complete migration for legacy Phase 3 accounts where
    the server invalidated the legacy auth_hash.
    
    Properties:
    1. Updates account_password_hash with Argon2id.
    2. Clears requires_password_migration flag.
    3. Revokes all active sessions for the account.
    4. Leaves kdf_salt, wrapped_vault_key, and all encrypted_records completely intact.
    5. Does NOT claim or provide any vault decryption or recovery without the vault master password.
    """
    normalized_username = username.strip().lower()
    stmt = select(Account).where(func.lower(Account.username) == normalized_username)
    account = db.execute(stmt).scalar_one_or_none()
    if not account:
        raise AccountNotFoundError(f"Account '{username}' not found")

    # Update account password
    account.account_password_hash = hash_password(new_account_password)
    account.requires_password_migration = False
    account.updated_at = datetime.now(timezone.utc)

    # Invalidate all active sessions for this account
    now = datetime.now(timezone.utc)
    sessions_stmt = select(Session).where(
        Session.account_id == account.id,
        Session.revoked_at.is_(None),
    )
    for s in db.execute(sessions_stmt).scalars().all():
        s.revoked_at = now

    db.commit()
    db.refresh(account)
    return account
