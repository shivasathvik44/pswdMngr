"""Pydantic request and response schemas for VaultSync API."""

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    """Account registration request.
    
    Receives auth_secret derived from client-side Argon2id + HKDF,
    along with client's KDF salt and optional initial wrapped vault key.
    """
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=255, description="Unique account username")
    auth_secret: str = Field(min_length=16, max_length=512, description="Client-derived authentication secret")
    kdf_salt: str = Field(min_length=16, max_length=64, description="Base64 encoded 16-byte KDF salt")
    wrapped_vault_key: str | None = Field(default=None, max_length=4096, description="Initial wrapped vault key envelope JSON")


class RegisterResponse(BaseModel):
    account_id: uuid.UUID
    username: str
    kdf_salt: str
    created_at: datetime


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=255)
    auth_secret: str = Field(min_length=16, max_length=512)
    device_name: str = Field(default="Unknown Device", max_length=128)
    device_id: str | None = Field(default=None, max_length=128)


class LoginResponse(BaseModel):
    session_token: str
    session_id: uuid.UUID
    account_id: uuid.UUID
    expires_at: datetime
    kdf_salt: str
    wrapped_vault_key: str | None


class SaltResponse(BaseModel):
    username: str
    kdf_salt: str


class VaultKeyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    wrapped_vault_key: str = Field(min_length=10, max_length=4096)


class SessionItem(BaseModel):
    id: uuid.UUID
    device_name: str
    device_id: str | None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime
    is_current: bool = False


class RecordCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(min_length=1, max_length=64, description="Client record UUID")
    ciphertext_payload: str = Field(
        min_length=10,
        max_length=2_097_152,  # 2 MiB bound
        description="Opaque EncryptedRecordEnvelope JSON string",
    )


class RecordUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1, description="Expected base revision for optimistic concurrency")
    ciphertext_payload: str = Field(
        min_length=10,
        max_length=2_097_152,
        description="Opaque EncryptedRecordEnvelope JSON string",
    )


class RecordResponse(BaseModel):
    record_id: str
    ciphertext_payload: str
    revision: int
    sync_cursor: int
    is_deleted: bool
    created_at: datetime
    updated_at: datetime


class RecordDeleteResponse(BaseModel):
    record_id: str
    revision: int
    sync_cursor: int
    is_deleted: bool = True


class ConflictResponse(BaseModel):
    detail: str
    record_id: str
    current_revision: int


class SyncResponse(BaseModel):
    items: list[RecordResponse]
    server_cursor: int
    next_cursor: int
    has_more: bool
