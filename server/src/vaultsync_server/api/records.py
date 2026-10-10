"""Encrypted record CRUD and optimistic concurrency endpoints."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
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

    now = datetime.now(timezone.utc)
    account.sync_cursor += 1

    if existing:
        if not existing.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Record already exists. Use PUT to update.",
            )
        # Resurrect previously tombstoned record
        existing.ciphertext_payload = req.ciphertext_payload
        existing.is_deleted = False
        existing.revision += 1
        existing.sync_cursor = account.sync_cursor
        existing.updated_at = now
        record = existing
    else:
        record = EncryptedRecord(
            record_id=req.record_id,
            account_id=account.id,
            ciphertext_payload=req.ciphertext_payload,
            revision=1,
            sync_cursor=account.sync_cursor,
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

    if record.revision != req.expected_revision:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Conflict: expected revision {req.expected_revision}, "
                f"but current revision is {record.revision}"
            ),
        )

    now = datetime.now(timezone.utc)
    account.sync_cursor += 1

    record.ciphertext_payload = req.ciphertext_payload
    record.revision += 1
    record.sync_cursor = account.sync_cursor
    record.updated_at = now

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


@router.delete(
    "/{record_id}",
    response_model=RecordDeleteResponse,
    summary="Delete record (create tombstone)",
)
async def delete_record(
    record_id: str,
    auth_data: Annotated[tuple[Account, Session], Depends(get_current_session)],
    db: Annotated[DbSession, Depends(get_db)],
    expected_revision: Annotated[int | None, Query(description="Optional revision guard")] = None,
) -> RecordDeleteResponse:
    """Tombstone a record to propagate deletion to synchronized clients."""
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

    if expected_revision is not None and record.revision != expected_revision:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Conflict: expected revision {expected_revision}, "
                f"but current revision is {record.revision}"
            ),
        )

    now = datetime.now(timezone.utc)
    account.sync_cursor += 1

    record.is_deleted = True
    record.revision += 1
    record.sync_cursor = account.sync_cursor
    record.ciphertext_payload = ""  # Purge ciphertext content
    record.updated_at = now

    db.commit()
    db.refresh(record)

    return RecordDeleteResponse(
        record_id=record.record_id,
        revision=record.revision,
        sync_cursor=record.sync_cursor,
        is_deleted=True,
    )
