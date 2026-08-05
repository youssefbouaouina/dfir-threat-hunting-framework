"""phase5 ioc feed automation: iocs table

Revision ID: 6f7a1b2c3d4e
Revises: 5f0a1c2d9b73
Create Date: 2026-08-04 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6f7a1b2c3d4e'
down_revision: Union[str, Sequence[str], None] = '5f0a1c2d9b73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Adds the F7 Ioc table (idempotent: skipped if already present).

    Persists automated intel-feed indicators with a (value, ioc_type, source)
    unique key so re-refreshes upsert instead of duplicating rows.
    """
    bind = op.get_bind()
    if not bind.dialect.has_table(bind, 'iocs'):
        op.create_table('iocs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('ioc_type', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('threat', sa.String(), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('active', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('value', 'ioc_type', 'source', name='uq_iocs_value_type_source')
        )
        op.create_index(op.f('ix_iocs_id'), 'iocs', ['id'], unique=False)
        op.create_index(op.f('ix_iocs_ioc_type'), 'iocs', ['ioc_type'], unique=False)
        op.create_index(op.f('ix_iocs_source'), 'iocs', ['source'], unique=False)
        op.create_index(op.f('ix_iocs_value'), 'iocs', ['value'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_iocs_value'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_source'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_ioc_type'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_id'), table_name='iocs')
    op.drop_table('iocs')
