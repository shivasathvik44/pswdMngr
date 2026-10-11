"""Two-credential security migration and database rate limiting table.

Revision ID: 0002_two_credential_architecture
Revises: 0001_initial_schema
Create Date: 2026-10-11 23:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0002_two_credential_architecture"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update accounts table to adopt independent account_password_hash
    with op.batch_alter_table("accounts", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("account_password_hash", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("requires_password_migration", sa.Boolean(), server_default="0", nullable=False)
        )
    
    # Invalidate legacy auth_hash and flag any existing accounts as requiring migration
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE accounts SET account_password_hash = 'MIGRATION_REQUIRED', "
            "requires_password_migration = 1 WHERE account_password_hash IS NULL"
        )
    )

    with op.batch_alter_table("accounts", schema=None) as batch_op:
        batch_op.alter_column("account_password_hash", nullable=False)
        batch_op.drop_column("auth_hash")

    # 2. Create auth_rate_limits table for multi-worker database-backed rate limiting
    op.create_table(
        "auth_rate_limits",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("identifier", sa.String(length=128), nullable=False),
        sa.Column("attempt_time", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_auth_rate_limits_id_time",
        "auth_rate_limits",
        ["identifier", "attempt_time"],
        unique=False,
    )


def downgrade() -> None:
    # 1. Drop auth_rate_limits table
    op.drop_index("ix_auth_rate_limits_id_time", table_name="auth_rate_limits")
    op.drop_table("auth_rate_limits")

    # 2. Revert accounts table
    with op.batch_alter_table("accounts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("auth_hash", sa.Text(), nullable=True))
        batch_op.drop_column("requires_password_migration")
        batch_op.drop_column("account_password_hash")
