"""FastAPI dependencies for authentication, authorization, and database access."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession, joinedload

from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, Session
from vaultsync_server.services.auth import hash_token

security = HTTPBearer(auto_error=False)


async def get_current_session(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(security)],
    db: Annotated[DbSession, Depends(get_db)],
) -> tuple[Account, Session]:
    """Validate incoming bearer token against active database sessions.
    
    Verifies that the session exists, has not been revoked, has not expired,
    and belongs to an active account. Updates session last_used_at timestamp.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials.strip()
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    stmt = (
        select(Session)
        .options(joinedload(Session.account))
        .where(
            Session.token_hash == token_hash,
            Session.revoked_at.is_(None),
        )
    )
    result = db.execute(stmt)
    session = result.scalar_one_or_none()

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate session expiration
    # Ensure timezone awareness for comparison
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    account = session.account
    if not account or not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Touch last_used_at
    session.last_used_at = now
    db.commit()

    return account, session


async def get_current_account(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
) -> Account:
    """Convenience dependency returning the authenticated Account."""
    return auth_data[0]
