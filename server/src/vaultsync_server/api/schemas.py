"""Pydantic request and response schemas for VaultSync API."""

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    """Account registration request adhering to the Two-Credential model.
    
    Receives account_password (used strictly for server authentication)
    along with client's public KDF salt and wrapped vault key envelope JSON.
    The vault master password never reaches the server.
    """
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=255, description="Unique account username")
    account_password: str = Field(min_length=8, max_length=256, description="Server account authentication password")
    kdf_salt: str = Field(min_length=16, max_length=64, description="Base64 encoded 16-byte KDF salt")
    wrapped_vault_key: str | None = Field(default=None, max_length=4096, description="Initial wrapped vault key envelope JSON")


class RegisterResponse(BaseModel):
    account_id: uuid.UUID
    username: str
    kdf_salt: str
    created_at: datetime


class LoginRequest(BaseModel):
    """Account login request using independent server account credentials."""
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=255)
    account_password: str = Field(min_length=8, max_length=256)
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


class AccountPasswordChangeRequest(BaseModel):
    """Request to change the server account password."""
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=8, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class VaultKeyUpdateRequest(BaseModel):
    """Request to update wrapped vault key envelope and optional fresh public KDF salt."""
    model_config = ConfigDict(extra="forbid")

    wrapped_vault_key: str = Field(min_length=10, max_length=4096)
    kdf_salt: str | None = Field(default=None, min_length=16, max_length=64)


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
