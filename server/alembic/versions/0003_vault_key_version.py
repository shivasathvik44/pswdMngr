"""Add vault_key_version to accounts table.

Revision ID: 0003_vault_key_version
Revises: 0002_two_credential_architecture
Create Date: 2026-10-24 22:00:00.000000

Supports atomic versioned updates to the wrapped vault key envelope and
prevents concurrent or stale envelope overwrites.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0003_vault_key_version"
down_revision: Union[str, None] = "0002_two_credential_architecture"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("accounts", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("vault_key_version", sa.Integer(), server_default="1", nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("accounts", schema=None) as batch_op:
        batch_op.drop_column("vault_key_version")
