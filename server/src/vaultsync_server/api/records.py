"""Encrypted record CRUD and optimistic concurrency endpoints."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.api.dependencies import get_current_session
from vaultsync_server.api.schemas import (
    RecordCreateRequest,
    RecordDeleteResponse,
    RecordResponse,
    RecordUpdateRequest,
)
from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope
from vaultsync_server.crypto.errors import CryptoError
from vaultsync_server.db.base import get_db
from vaultsync_server.db.models import Account, EncryptedRecord, Session

router = APIRouter(prefix="/records", tags=["Records"])


@router.post(
    "",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new encrypted record",
)
async def create_record(
    req: RecordCreateRequest,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> RecordResponse:
    """Upload an opaque encrypted record.
    
    The server validates the envelope structure and record_id matching,
    but cannot read or decrypt the vault payload.
    """
    account, _ = auth_data

    # Validate outer transport envelope structure
    try:
        envelope = EncryptedRecordEnvelope.from_json(req.ciphertext_payload)
        if envelope.record_id != req.record_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload record_id does not match request record_id",
            )
    except CryptoError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed encrypted envelope: {exc}",
        ) from exc

    # Check for existing record under this account
    stmt = select(EncryptedRecord).where(
        EncryptedRecord.account_id == account.id,
        EncryptedRecord.record_id == req.record_id,
    )
    existing = db.execute(stmt).scalar_one_or_none()

    if existing and not existing.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Record already exists. Use PUT to update.",
        )

    # Atomically allocate next sync cursor for this account in the same transaction
    cursor_stmt = (
        update(Account)
        .where(Account.id == account.id)
        .values(sync_cursor=Account.sync_cursor + 1)
        .returning(Account.sync_cursor)
    )
    new_cursor = db.execute(cursor_stmt).scalar_one()
    now = datetime.now(timezone.utc)

    if existing:
        # Resurrect previously tombstoned record
        existing.ciphertext_payload = req.ciphertext_payload
        existing.is_deleted = False
        existing.revision += 1
        existing.sync_cursor = new_cursor
        existing.updated_at = now
        record = existing
    else:
        record = EncryptedRecord(
            record_id=req.record_id,
            account_id=account.id,
            ciphertext_payload=req.ciphertext_payload,
            revision=1,
            sync_cursor=new_cursor,
            is_deleted=False,
            created_at=now,
            updated_at=now,
        )
        db.add(record)

    db.commit()
    db.refresh(record)

    return RecordResponse(
        record_id=record.record_id,
        ciphertext_payload=record.ciphertext_payload,
        revision=record.revision,
        sync_cursor=record.sync_cursor,
        is_deleted=record.is_deleted,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "/{record_id}",
    response_model=RecordResponse,
    summary="Get single encrypted record",
)
async def get_record(
    record_id: str,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> RecordResponse:
    """Fetch an encrypted record strictly scoped to the authenticated account."""
    account, _ = auth_data

    stmt = select(EncryptedRecord).where(
        EncryptedRecord.account_id == account.id,
        EncryptedRecord.record_id == record_id,
    )
    record = db.execute(stmt).scalar_one_or_none()

    if not record or record.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Record not found",
        )

    return RecordResponse(
        record_id=record.record_id,
        ciphertext_payload=record.ciphertext_payload,
        revision=record.revision,
        sync_cursor=record.sync_cursor,
        is_deleted=record.is_deleted,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.put(
    "/{record_id}",
    response_model=RecordResponse,
    summary="Update encrypted record with optimistic concurrency check",
)
async def update_record(
    record_id: str,
    req: RecordUpdateRequest,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
) -> RecordResponse:
    """Update an encrypted record.
    
    Rejects the update with HTTP 409 Conflict if expected_revision does not match
    the current server revision, preventing silent overwrite of concurrent modifications.
    """
    account, _ = auth_data

    try:
        envelope = EncryptedRecordEnvelope.from_json(req.ciphertext_payload)
        if envelope.record_id != record_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload record_id does not match URL record_id",
            )
    except CryptoError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed encrypted envelope: {exc}",
        ) from exc

    now = datetime.now(timezone.utc)

    # Atomic conditional update enforcing expected_revision directly in SQL
    update_stmt = (
        update(EncryptedRecord)
        .where(
            EncryptedRecord.account_id == account.id,
            EncryptedRecord.record_id == record_id,
            EncryptedRecord.revision == req.expected_revision,
            EncryptedRecord.is_deleted.is_(False),
        )
        .values(
            ciphertext_payload=req.ciphertext_payload,
            revision=EncryptedRecord.revision + 1,
            updated_at=now,
        )
    )
    result = db.execute(update_stmt)

    if result.rowcount == 0:
        # Check whether record exists or has revision conflict
        record = db.execute(
            select(EncryptedRecord).where(
                EncryptedRecord.account_id == account.id,
                EncryptedRecord.record_id == record_id,
            )
        ).scalar_one_or_none()

        if not record or record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Record not found",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Conflict: expected revision {req.expected_revision}, "
                f"but current revision is {record.revision}"
            ),
        )

    # Allocate next sync cursor for this account in the same transaction
    cursor_stmt = (
        update(Account)
        .where(Account.id == account.id)
        .values(sync_cursor=Account.sync_cursor + 1)
        .returning(Account.sync_cursor)
    )
    new_cursor = db.execute(cursor_stmt).scalar_one()

    # Assign cursor to updated record
    set_cursor_stmt = (
        update(EncryptedRecord)
        .where(
            EncryptedRecord.account_id == account.id,
            EncryptedRecord.record_id == record_id,
        )
        .values(sync_cursor=new_cursor)
        .returning(EncryptedRecord)
    )
    updated_record = db.execute(set_cursor_stmt).scalar_one()

    db.commit()
    db.refresh(updated_record)

    return RecordResponse(
        record_id=updated_record.record_id,
        ciphertext_payload=updated_record.ciphertext_payload,
        revision=updated_record.revision,
        sync_cursor=updated_record.sync_cursor,
        is_deleted=updated_record.is_deleted,
        created_at=updated_record.created_at,
        updated_at=updated_record.updated_at,
    )


@router.delete(
    "/{record_id}",
    response_model=RecordDeleteResponse,
    summary="Delete record (create tombstone)",
)
async def delete_record(
    record_id: str,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
    expected_revision: Annotated[int | None, Query(description="Expected base revision for optimistic concurrency")] = None,
) -> RecordDeleteResponse:
    """Tombstone a record to propagate deletion to synchronized clients.

    Requires expected_revision to prevent stale clients from deleting records
    modified concurrently elsewhere.
    """
    account, _ = auth_data

    if expected_revision is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required query parameter: expected_revision",
        )

    now = datetime.now(timezone.utc)

    # Atomic conditional update for tombstone creation directly in SQL
    tombstone_stmt = (
        update(EncryptedRecord)
        .where(
            EncryptedRecord.account_id == account.id,
            EncryptedRecord.record_id == record_id,
            EncryptedRecord.revision == expected_revision,
            EncryptedRecord.is_deleted.is_(False),
        )
        .values(
            is_deleted=True,
            ciphertext_payload="",
            revision=EncryptedRecord.revision + 1,
            updated_at=now,
        )
    )
    result = db.execute(tombstone_stmt)

    if result.rowcount == 0:
        # Check whether record exists or is already deleted/modified
        record = db.execute(
            select(EncryptedRecord).where(
                EncryptedRecord.account_id == account.id,
                EncryptedRecord.record_id == record_id,
            )
        ).scalar_one_or_none()

        if not record or record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Record not found",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Conflict: expected revision {expected_revision}, "
                f"but current revision is {record.revision}"
            ),
        )

    # Allocate next sync cursor for this account in the same transaction
    cursor_stmt = (
        update(Account)
        .where(Account.id == account.id)
        .values(sync_cursor=Account.sync_cursor + 1)
        .returning(Account.sync_cursor)
    )
    new_cursor = db.execute(cursor_stmt).scalar_one()

    # Assign cursor to tombstoned record
    set_cursor_stmt = (
        update(EncryptedRecord)
        .where(
            EncryptedRecord.account_id == account.id,
            EncryptedRecord.record_id == record_id,
        )
        .values(sync_cursor=new_cursor)
        .returning(EncryptedRecord)
    )
    tombstoned_record = db.execute(set_cursor_stmt).scalar_one()

    db.commit()
    db.refresh(tombstoned_record)

    return RecordDeleteResponse(
        record_id=tombstoned_record.record_id,
        revision=tombstoned_record.revision,
        sync_cursor=tombstoned_record.sync_cursor,
        is_deleted=True,
    )
