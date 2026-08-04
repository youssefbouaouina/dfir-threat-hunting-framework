"""phase4 host criticality (F5 severity amplifier)

Revision ID: 5f0a1c2d9b73
Revises: 4a1f2c9d3b70
Create Date: 2026-08-03 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5f0a1c2d9b73'
down_revision: Union[str, Sequence[str], None] = '4a1f2c9d3b70'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    from sqlalchemy import inspect

    return any(c["name"] == column for c in inspect(bind).get_columns(table))


def upgrade() -> None:
    """Adds the endpoint `criticality` column (default 'standard').

    Idempotent: skipped if the column already exists (safe on partial runs).
    """
    bind = op.get_bind()
    if _has_column(bind, "endpoints", "criticality"):
        return
    op.add_column(
        "endpoints",
        sa.Column("criticality", sa.String(), nullable=False, server_default="standard"),
    )


def downgrade() -> None:
    """Downgrade schema (best-effort, reverse of upgrade)."""
    bind = op.get_bind()
    if _has_column(bind, "endpoints", "criticality"):
        op.drop_column("endpoints", "criticality")
