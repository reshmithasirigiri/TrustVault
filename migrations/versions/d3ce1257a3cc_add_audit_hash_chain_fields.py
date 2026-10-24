
"""add audit hash chain fields

Revision ID: d3ce1257a3cc
Revises: bbad60826cca
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d3ce1257a3cc"
down_revision: Union[str, Sequence[str], None] = "bbad60826cca"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column(
            "previous_hash",
            sa.String(length=64),
            nullable=False,
            server_default="0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )

    op.add_column(
        "audit_logs",
        sa.Column(
            "entry_hash",
            sa.String(length=64),
            nullable=False,
            server_default="0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "previous_hash")
