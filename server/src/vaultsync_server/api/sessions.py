"""Device session management and revocation endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.api.dependencies import get_current_session
from vaultsync_server.api.schemas import SessionItem
from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, Session

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.get(
    "",
    response_model=list[SessionItem],
    summary="List active device sessions",
)
async def list_sessions(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> list[SessionItem]:
    """Retrieve all active unrevoked and unexpired sessions for the authenticated user."""
    account, current_session = auth_data
    now = datetime.now(timezone.utc)

    stmt = (
        select(Session)
        .where(
            Session.account_id == account.id,
            Session.revoked_at.is_(None),
            Session.expires_at > now,
        )
        .order_by(Session.last_used_at.desc())
    )
    results = db.execute(stmt).scalars().all()

    items = []
    for s in results:
        items.append(
            SessionItem(
                id=s.id,
                device_name=s.device_name,
                device_id=s.device_id,
                created_at=s.created_at,
                expires_at=s.expires_at,
                last_used_at=s.last_used_at,
                is_current=(s.id == current_session.id),
            )
        )
    return items


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke specific device session",
)
async def revoke_session(
    session_id: uuid.UUID,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> dict[str, str]:
    """Revoke a specific session belonging to the authenticated account."""
    account, _ = auth_data
    stmt = select(Session).where(
        Session.id == session_id,
        Session.account_id == account.id,
    )
    target_session = db.execute(stmt).scalar_one_or_none()

    if not target_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    target_session.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "message": "Session successfully revoked"}


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    summary="Revoke all sessions for account",
)
async def revoke_all_sessions(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> dict[str, str]:
    """Revoke all sessions for the account, forcing re-authentication on all devices."""
    account, _ = auth_data
    now = datetime.now(timezone.utc)

    stmt = (
        update(Session)
        .where(
            Session.account_id == account.id,
            Session.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    db.execute(stmt)
    db.commit()
    return {"status": "ok", "message": "All sessions revoked"}
