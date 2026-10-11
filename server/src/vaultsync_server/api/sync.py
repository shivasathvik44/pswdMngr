"""Incremental synchronization endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.api.dependencies import get_current_session
from vaultsync_server.api.schemas import RecordResponse, SyncResponse
from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, EncryptedRecord, Session

router = APIRouter(prefix="/sync", tags=["Synchronization"])


@router.get(
    "",
    response_model=SyncResponse,
    summary="Fetch incremental changes since cursor",
)
async def sync_changes(
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
    since_cursor: Annotated[int, Query(ge=0, description="Resume cursor (default: 0)")] = 0,
    limit: Annotated[int, Query(ge=1, le=500, description="Max batch size (default: 100)")] = 100,
) -> SyncResponse:
    """Fetch all changed records and deletion tombstones with sync_cursor > since_cursor.
    
    Supports offline-first clients resuming synchronization after connectivity loss.
    """
    account, _ = auth_data

    stmt = (
        select(EncryptedRecord)
        .where(
            EncryptedRecord.account_id == account.id,
            EncryptedRecord.sync_cursor > since_cursor,
        )
        .order_by(EncryptedRecord.sync_cursor.asc(), EncryptedRecord.id.asc())
        .limit(limit + 1)
    )
    records = db.execute(stmt).scalars().all()

    has_more = len(records) > limit
    selected_records = records[:limit] if has_more else records

    items = [
        RecordResponse(
            record_id=r.record_id,
            ciphertext_payload=r.ciphertext_payload,
            revision=r.revision,
            sync_cursor=r.sync_cursor,
            is_deleted=r.is_deleted,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in selected_records
    ]

    next_cursor = selected_records[-1].sync_cursor if selected_records else since_cursor

    return SyncResponse(
        items=items,
        server_cursor=account.sync_cursor,
        next_cursor=next_cursor,
        has_more=has_more,
    )
