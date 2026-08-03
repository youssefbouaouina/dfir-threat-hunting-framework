"""phase4 RBAC: endpoint team + tamper-evident audit chain

Revision ID: 4a1f2c9d3b70
Revises: e19d4f2a7c10
Create Date: 2026-08-03 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4a1f2c9d3b70'
down_revision: Union[str, Sequence[str], None] = 'e19d4f2a7c10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    from sqlalchemy import inspect

    return any(c["name"] == column for c in inspect(bind).get_columns(table))


def upgrade() -> None:
    """Adds F4 RBAC/immutable-audit columns.

    Idempotent via per-column existence checks so a partial run or a schema
    that already received them (e.g. re-run on a dev DB) is safe. The team
    column stays nullable at the DB level (SQLite cannot ALTER a column's
    nullability); the service layer defaults it to 'default' on read.
    """
    bind = op.get_bind()
    if not _has_column(bind, "endpoints", "team"):
        op.add_column(
            "endpoints",
            sa.Column("team", sa.String(), nullable=True),
        )
        op.execute("UPDATE endpoints SET team = 'default' WHERE team IS NULL")
        op.create_index(op.f("ix_endpoints_team"), "endpoints", ["team"], unique=False)
    if not _has_column(bind, "audit_logs", "prev_hash"):
        op.add_column("audit_logs", sa.Column("prev_hash", sa.String(), nullable=True))
    if not _has_column(bind, "audit_logs", "record_hash"):
        op.add_column("audit_logs", sa.Column("record_hash", sa.String(), nullable=True))
        op.create_index(
            op.f("ix_audit_logs_record_hash"), "audit_logs", ["record_hash"], unique=False
        )


def downgrade() -> None:
    """Downgrade schema (best-effort, reverse of upgrade)."""
    bind = op.get_bind()
    if _has_column(bind, "audit_logs", "record_hash"):
        op.drop_index(op.f("ix_audit_logs_record_hash"), table_name="audit_logs")
        op.drop_column("audit_logs", "record_hash")
    if _has_column(bind, "audit_logs", "prev_hash"):
        op.drop_column("audit_logs", "prev_hash")
    if _has_column(bind, "endpoints", "team"):
        op.drop_index(op.f("ix_endpoints_team"), table_name="endpoints")
        op.drop_column("endpoints", "team")
