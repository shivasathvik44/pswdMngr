"""Authentication and account lifecycle endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.api.dependencies import get_current_session
from vaultsync_server.api.schemas import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    SaltResponse,
    VaultKeyUpdateRequest,
)
from vaultsync_server.config import settings
from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, Session
from vaultsync_server.services.auth import (
    generate_session_token,
    hash_auth_secret,
    rate_limiter,
    verify_auth_secret,
)

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
    """Register a new account.
    
    The server stores the client-derived auth_secret (hashed via Argon2id)
    and the client's KDF salt. The server never receives the master password or KEK.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"reg:{client_ip}"
    if rate_limiter.is_rate_limited(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
        )

    # Check for existing username
    stmt = select(Account).where(Account.username == req.username)
    existing = db.execute(stmt).scalar_one_or_none()
    if existing:
        rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    auth_hash = hash_auth_secret(req.auth_secret)
    account = Account(
        username=req.username,
        auth_hash=auth_hash,
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
    """Authenticate with client-derived auth_secret and issue a session bearer token."""
    client_ip = request.client.host if request.client else "unknown"
    ip_key = f"auth:ip:{client_ip}"
    user_key = f"auth:user:{req.username}"

    if rate_limiter.is_rate_limited(ip_key) or rate_limiter.is_rate_limited(user_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait before trying again.",
        )

    stmt = select(Account).where(Account.username == req.username)
    account = db.execute(stmt).scalar_one_or_none()

    if not account or not account.is_active:
        rate_limiter.record_failure(ip_key)
        rate_limiter.record_failure(user_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not verify_auth_secret(account.auth_hash, req.auth_secret):
        rate_limiter.record_failure(ip_key)
        rate_limiter.record_failure(user_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Reset rate limiting on successful login
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


@router.get(
    "/salt",
    response_model=SaltResponse,
    summary="Retrieve user KDF salt for client key derivation",
)
async def get_user_salt(
    username: str,
    db: Annotated[DbSession, Depends(get_db)],
) -> SaltResponse:
    """Retrieve public KDF salt associated with a username so client can derive auth_secret."""
    stmt = select(Account).where(Account.username == username)
    account = db.execute(stmt).scalar_one_or_none()
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )
    return SaltResponse(username=account.username, kdf_salt=account.kdf_salt)


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
    """Store or update the user's WrappedKeyEnvelope (e.g. after master password change)."""
    account, _ = auth_data
    account.wrapped_vault_key = req.wrapped_vault_key
    account.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "message": "Wrapped vault key updated successfully"}
