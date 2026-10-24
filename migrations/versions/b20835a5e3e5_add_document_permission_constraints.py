"""add document permission constraints

Revision ID: b20835a5e3e5
Revises: d3ce1257a3cc
Create Date: 2026-10-22 20:43:29.577354

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b20835a5e3e5'
down_revision: Union[str, Sequence[str], None] = 'd3ce1257a3cc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint(
        "uq_document_permission_user",
        "document_permissions",
        ["document_id", "user_id"],
    )
    op.create_check_constraint(
        "ck_document_permission_valid",
        "document_permissions",
        "permission IN ('READ', 'EDIT')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "ck_document_permission_valid",
        "document_permissions",
        type_="check",
    )
    op.drop_constraint(
        "uq_document_permission_user",
        "document_permissions",
        type_="unique",
    )