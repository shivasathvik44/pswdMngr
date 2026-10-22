"""Authentication and account lifecycle endpoints."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.api.dependencies import get_current_session
from vaultsync_server.api.schemas import (
    AccountPasswordChangeRequest,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    SaltResponse,
    VaultKeyUpdateRequest,
)
from vaultsync_server.config import settings
from vaultsync_server.crypto.envelope import WrappedKeyEnvelope, b64decode, b64encode
from vaultsync_server.crypto.errors import CryptoError
from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, Session
from vaultsync_server.services.auth import (
    DUMMY_PASSWORD_HASH,
    db_rate_limiter,
    generate_session_token,
    get_client_ip,
    hash_password,
    rate_limiter,
    verify_password,
)

def get_synthetic_salt_key() -> bytes:
    """Derive dedicated HMAC key for synthetic salt generation from configured server secret."""
    secret = (settings.server_secret_key or "").encode("utf-8")
    return hmac.new(secret, b"vaultsync:salt:synthetic:v1", hashlib.sha256).digest()


SYNTHETIC_SALT_KEY: Final[bytes] = get_synthetic_salt_key()


def generate_synthetic_salt(username: str) -> str:
    """Generate deterministic, valid-format 16-byte base64 salt for non-existent users."""
    key = get_synthetic_salt_key()
    normalized = username.strip().lower().encode("utf-8")
    raw = hmac.new(key, normalized, hashlib.sha256).digest()[:16]
    return b64encode(raw)


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    req: RegisterRequest,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
) -> RegisterResponse:
    """Register a new account adhering to Two-Credential architecture.
    
    The server stores the Argon2id hash of the account password and the public KDF salt.
    The server never receives the master password, KEK, or unencrypted vault key.
    """
    client_ip = get_client_ip(request)
    rate_key = f"reg:{client_ip}"
    if db_rate_limiter.is_rate_limited(db, rate_key) or rate_limiter.is_rate_limited(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
        )

    # Validate kdf_salt encoding and length
    try:
        b64decode(req.kdf_salt, expected_length=16)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid kdf_salt encoding or length: {exc}",
        )

    # Validate wrapped_vault_key envelope if provided
    if req.wrapped_vault_key is not None:
        try:
            WrappedKeyEnvelope.from_json(req.wrapped_vault_key)
        except (CryptoError, Exception) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid wrapped_vault_key envelope: {exc}",
            )

    # Check for existing username case-insensitively to prevent identity collisions and rate-limit ambiguity
    normalized_username = req.username.strip().lower()
    stmt = select(Account).where(func.lower(Account.username) == normalized_username)
    existing = db.execute(stmt).scalar_one_or_none()
    if existing:
        db_rate_limiter.record_failure(db, rate_key)
        rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    account_password_hash = hash_password(req.account_password)
    account = Account(
        username=req.username,
        account_password_hash=account_password_hash,
        kdf_salt=req.kdf_salt,
        wrapped_vault_key=req.wrapped_vault_key,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    return RegisterResponse(
        account_id=account.id,
        username=account.username,
        kdf_salt=account.kdf_salt,
        created_at=account.created_at,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate account and establish device session",
)
async def login(
    req: LoginRequest,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
) -> LoginResponse:
    """Authenticate with independent server account password and issue a session bearer token."""
    client_ip = get_client_ip(request)
    normalized_username = req.username.strip().lower()
    ip_key = f"auth:ip:{client_ip}"
    user_key = f"auth:user:{normalized_username}"

    if (
        db_rate_limiter.is_rate_limited(db, ip_key)
        or db_rate_limiter.is_rate_limited(db, user_key)
        or rate_limiter.is_rate_limited(ip_key)
        or rate_limiter.is_rate_limited(user_key)
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait before trying again.",
        )

    stmt = select(Account).where(func.lower(Account.username) == normalized_username)
    account = db.execute(stmt).scalar_one_or_none()

    if not account or not account.is_active:
        # Constant-time dummy verification to mitigate username enumeration via timing attacks
        verify_password(DUMMY_PASSWORD_HASH, req.account_password)
        db_rate_limiter.record_failure(db, ip_key)
        db_rate_limiter.record_failure(db, user_key)
        rate_limiter.record_failure(ip_key)
        rate_limiter.record_failure(user_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if account.requires_password_migration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account requires password migration. Please perform password migration.",
        )

    if not verify_password(account.account_password_hash, req.account_password):
        db_rate_limiter.record_failure(db, ip_key)
        db_rate_limiter.record_failure(db, user_key)
        rate_limiter.record_failure(ip_key)
        rate_limiter.record_failure(user_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Reset rate limiting on successful login
    db_rate_limiter.reset(db, user_key)
    db_rate_limiter.reset(db, ip_key)
    rate_limiter.reset(user_key)
    rate_limiter.reset(ip_key)

    raw_token, token_hash = generate_session_token()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=settings.session_expiry_hours)

    session = Session(
        account_id=account.id,
        device_name=req.device_name,
        device_id=req.device_id,
        token_hash=token_hash,
        created_at=now,
        expires_at=expires_at,
        last_used_at=now,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return LoginResponse(
        session_token=raw_token,
        session_id=session.id,
        account_id=account.id,
        expires_at=expires_at,
        kdf_salt=account.kdf_salt,
        wrapped_vault_key=account.wrapped_vault_key,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke current session",
)
async def logout(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> dict[str, str]:
    """Revoke the calling device session immediately."""
    _, session = auth_data
    session.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "message": "Session successfully revoked"}


@router.put(
    "/password",
    status_code=status.HTTP_200_OK,
    summary="Change account password",
)
async def change_account_password(
    req: AccountPasswordChangeRequest,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
) -> dict[str, str]:
    """Change server account password.
    
    Verifies current account password and updates the stored Argon2id hash.
    Leaves wrapped vault key, KDF salt, and encrypted records completely intact.
    Invalidates all other active sessions for the account.
    """
    account, current_session = auth_data
    client_ip = get_client_ip(request)
    pwd_key = f"auth:pwd:{account.id}"
    ip_key = f"auth:pwd_ip:{client_ip}"

    if (
        db_rate_limiter.is_rate_limited(db, pwd_key)
        or db_rate_limiter.is_rate_limited(db, ip_key)
        or rate_limiter.is_rate_limited(pwd_key)
        or rate_limiter.is_rate_limited(ip_key)
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed password change attempts. Please wait before trying again.",
        )

    if not verify_password(account.account_password_hash, req.current_password):
        db_rate_limiter.record_failure(db, pwd_key)
        db_rate_limiter.record_failure(db, ip_key)
        rate_limiter.record_failure(pwd_key)
        rate_limiter.record_failure(ip_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current account password incorrect",
        )

    db_rate_limiter.reset(db, pwd_key)
    db_rate_limiter.reset(db, ip_key)
    rate_limiter.reset(pwd_key)
    rate_limiter.reset(ip_key)

    account.account_password_hash = hash_password(req.new_password)
    account.requires_password_migration = False
    account.updated_at = datetime.now(timezone.utc)

    # Invalidate all other active sessions for this account
    now = datetime.now(timezone.utc)
    stmt = (
        select(Session)
        .where(
            Session.account_id == account.id,
            Session.id != current_session.id,
            Session.revoked_at.is_(None),
        )
    )
    other_sessions = db.execute(stmt).scalars().all()
    for s in other_sessions:
        s.revoked_at = now

    db.commit()
    return {"status": "ok", "message": "Account password updated successfully"}


@router.get(
    "/salt",
    response_model=SaltResponse,
    summary="Retrieve user KDF salt for client key derivation",
)
async def get_user_salt(
    username: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
) -> SaltResponse:
    """Retrieve public KDF salt associated with a username without disclosing account existence."""
    client_ip = get_client_ip(request)
    normalized_username = username.strip().lower()
    ip_key = f"salt:ip:{client_ip}"

    # Rate limit by IP to prevent rapid enumeration scraping and endpoint flooding
    if db_rate_limiter.is_rate_limited(db, ip_key) or rate_limiter.is_rate_limited(ip_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many salt retrieval attempts. Please wait before trying again.",
        )

    # Record lookup attempt for IP rate limiting
    db_rate_limiter.record_failure(db, ip_key)
    rate_limiter.record_failure(ip_key)

    stmt = select(Account).where(func.lower(Account.username) == normalized_username)
    account = db.execute(stmt).scalar_one_or_none()
    if account:
        return SaltResponse(username=account.username, kdf_salt=account.kdf_salt)

    # Return deterministic synthetic salt for non-existent account with HTTP 200
    # Observers receive identical 200 OK responses with valid 16-byte base64 salts
    synthetic_salt = generate_synthetic_salt(normalized_username)
    return SaltResponse(username=username, kdf_salt=synthetic_salt)


@router.put(
    "/vault-key",
    status_code=status.HTTP_200_OK,
    summary="Upload or update encrypted wrapped vault key envelope",
)
async def update_vault_key(
    req: VaultKeyUpdateRequest,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> dict[str, str]:
    """Store or update the user's WrappedKeyEnvelope (e.g. after master password change).
    
    Validates envelope format and optional public KDF salt.
    Encrypted records and account password hash remain untouched.
    """
    account, _ = auth_data

    # Validate wrapped vault key envelope format
    try:
        WrappedKeyEnvelope.from_json(req.wrapped_vault_key)
    except (CryptoError, Exception) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid wrapped vault key envelope: {exc}",
        )

    # Optional KDF salt update (when changing master password)
    if req.kdf_salt is not None:
        try:
            b64decode(req.kdf_salt, expected_length=16)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid kdf_salt: {exc}",
            )
        account.kdf_salt = req.kdf_salt

    account.wrapped_vault_key = req.wrapped_vault_key
    account.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "message": "Wrapped vault key updated successfully"}


@router.get(
    "/vault-key",
    status_code=status.HTTP_200_OK,
    summary="Retrieve current wrapped vault key envelope and salt",
)
async def get_vault_key(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
) -> dict[str, str | None]:
    """Retrieve the current wrapped vault key envelope and KDF salt for the calling session."""
    account, _ = auth_data
    return {
        "wrapped_vault_key": account.wrapped_vault_key,
        "kdf_salt": account.kdf_salt,
    }

