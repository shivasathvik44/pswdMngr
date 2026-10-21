"""SQLAlchemy 2.0 ORM models for VaultSync Server."""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vaultsync_server.db.base import Base


class Account(Base):
    """User account entity adhering to the Two-Credential security model.
    
    Stores:
    - account_password_hash: Argon2id hash of the server account password.
    - kdf_salt: Public client-side salt used by client for vault master password KEK derivation.
    - wrapped_vault_key: Client-encrypted WrappedKeyEnvelope JSON.
    - sync_cursor: Monotonically increasing mutation sequence counter.
    
    The server NEVER receives or stores the vault master password, KEK, or VEK.
    """

    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    account_password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    kdf_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_vault_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_cursor: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_password_migration: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    sessions: Mapped[list["Session"]] = relationship(
        "Session",
        back_populates="account",
        cascade="all, delete-orphan",
    )
    records: Mapped[list["EncryptedRecord"]] = relationship(
        "EncryptedRecord",
        back_populates="account",
        cascade="all, delete-orphan",
    )


class Session(Base):
    """Device session and authentication token verifier.
    
    Only stores the SHA-256 verifier hash of the session token.
    The raw bearer token is never persisted in the database.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    device_name: Mapped[str] = mapped_column(String(128), default="Unknown Device", nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    account: Mapped["Account"] = relationship("Account", back_populates="sessions")


class EncryptedRecord(Base):
    """Encrypted vault record entity.
    
    Stores client-encrypted opaque ciphertext envelopes.
    The server cannot read or decrypt the contents.
    Enforces optimistic concurrency via revision numbers and deletion tombstones.
    """

    __tablename__ = "encrypted_records"
    __table_args__ = (
        UniqueConstraint("account_id", "record_id", name="uq_account_record_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    record_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    ciphertext_payload: Mapped[str] = mapped_column(Text, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    sync_cursor: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
        nullable=False,
    )

    account: Mapped["Account"] = relationship("Account", back_populates="records")


class AuthRateLimit(Base):
    """Database-backed rate limit event log for multi-worker abuse prevention."""

    __tablename__ = "auth_rate_limits"
    __table_args__ = (
        Index("ix_auth_rate_limits_id_time", "identifier", "attempt_time"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_time: Mapped[float] = mapped_column(Float, nullable=False)
