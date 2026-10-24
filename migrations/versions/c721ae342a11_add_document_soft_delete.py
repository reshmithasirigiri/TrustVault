"""add document soft delete flag

Revision ID: c721ae342a11
Revises: b20835a5e3e5
Create Date: 2026-10-23
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "c721ae342a11"
down_revision: Union[str, Sequence[str], None] = "b20835a5e3e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column("documents", sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False))

def downgrade() -> None:
    op.drop_column("documents", "is_deleted")
