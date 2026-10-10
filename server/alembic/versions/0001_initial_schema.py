"""Initial database schema for VaultSync.

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-11 00:38:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Accounts table
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("auth_hash", sa.Text(), nullable=False),
        sa.Column("kdf_salt", sa.String(length=64), nullable=False),
        sa.Column("wrapped_vault_key", sa.Text(), nullable=True),
        sa.Column("sync_cursor", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_accounts_username", "accounts", ["username"], unique=True)

    # 2. Sessions table
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("device_name", sa.String(length=128), server_default="Unknown Device", nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_account_id", "sessions", ["account_id"], unique=False)
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"], unique=False)
    op.create_index("ix_sessions_revoked_at", "sessions", ["revoked_at"], unique=False)

    # 3. Encrypted records table
    op.create_table(
        "encrypted_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("ciphertext_payload", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("sync_cursor", sa.BigInteger(), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "record_id", name="uq_account_record_id"),
    )
    op.create_index("ix_encrypted_records_record_id", "encrypted_records", ["record_id"], unique=False)
    op.create_index("ix_encrypted_records_account_id", "encrypted_records", ["account_id"], unique=False)
    op.create_index("ix_encrypted_records_sync_cursor", "encrypted_records", ["sync_cursor"], unique=False)
    op.create_index("ix_encrypted_records_is_deleted", "encrypted_records", ["is_deleted"], unique=False)
    op.create_index("ix_encrypted_records_updated_at", "encrypted_records", ["updated_at"], unique=False)


def downgrade() -> None:
    op.drop_table("encrypted_records")
    op.drop_table("sessions")
    op.drop_table("accounts")
