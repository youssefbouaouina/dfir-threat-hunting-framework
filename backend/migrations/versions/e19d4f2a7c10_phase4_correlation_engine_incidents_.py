"""phase4 correlation engine: incidents + incident_detections

Revision ID: e19d4f2a7c10
Revises: ca41c1ba0e02
Create Date: 2026-08-03 07:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e19d4f2a7c10'
down_revision: Union[str, Sequence[str], None] = 'ca41c1ba0e02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Adds the F2 correlation tables (incidents + incident_detections).

    Both are brand-new tables (idempotent: skipped if already present), so this
    works on a fresh DB and on existing Phase-3 databases alike.
    """
    bind = op.get_bind()
    if not bind.dialect.has_table(bind, 'incidents'):
        op.create_table('incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('signature', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('host_count', sa.Integer(), nullable=True),
        sa.Column('detection_count', sa.Integer(), nullable=True),
        sa.Column('technique_ids', sa.Text(), nullable=True),
        sa.Column('tactic', sa.String(), nullable=True),
        sa.Column('hosts', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
        op.create_index(op.f('ix_incidents_signature'), 'incidents', ['signature'], unique=True)
    if not bind.dialect.has_table(bind, 'incident_detections'):
        op.create_table('incident_detections',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('detection_id', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_incident_detections_detection_id'), 'incident_detections', ['detection_id'], unique=False)
        op.create_index(op.f('ix_incident_detections_id'), 'incident_detections', ['id'], unique=False)
        op.create_index(op.f('ix_incident_detections_incident_id'), 'incident_detections', ['incident_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_incident_detections_incident_id'), table_name='incident_detections')
    op.drop_index(op.f('ix_incident_detections_id'), table_name='incident_detections')
    op.drop_index(op.f('ix_incident_detections_detection_id'), table_name='incident_detections')
    op.drop_table('incident_detections')
    op.drop_index(op.f('ix_incidents_signature'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_id'), table_name='incidents')
    op.drop_table('incidents')
