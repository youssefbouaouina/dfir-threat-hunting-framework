"""phase5 perf: composite query indexes + stats_snapshots table

Revision ID: 7a8b1c2d3e4f
Revises: 6f7a1b2c3d4e
Create Date: 2026-08-04 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7a8b1c2d3e4f'
down_revision: Union[str, Sequence[str], None] = '6f7a1b2c3d4e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, index_name, columns) — hot query paths from the detection sweep,
# team-scoped listing, audit filtering and incident dashboards.
_COMPOSITE_INDEXES = [
    ('artifacts', 'ix_artifacts_processed_ingested', ['processed', 'ingested_at']),
    ('detections', 'ix_detections_host_detected', ['host', 'detected_at']),
    ('detections', 'ix_detections_rule_detected', ['rule_id', 'detected_at']),
    ('audit_logs', 'ix_audit_logs_action_created', ['action', 'created_at']),
    ('incidents', 'ix_incidents_status_updated', ['status', 'updated_at']),
]


def upgrade() -> None:
    """Adds F8 composite indexes + the stats_snapshots materialization table.

    Every step is idempotent (inspector-guarded) so the migration works on a
    fresh DB and on an existing Phase-5 database alike.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table, index_name, columns in _COMPOSITE_INDEXES:
        if not inspector.has_table(table):
            continue
        existing = {idx["name"] for idx in inspector.get_indexes(table)}
        if index_name not in existing:
            op.create_index(index_name, table, columns, unique=False)

    if not inspector.has_table('stats_snapshots'):
        op.create_table('stats_snapshots',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('metric', sa.String(), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('computed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('metric', name='uq_stats_snapshots_metric')
        )
        op.create_index(op.f('ix_stats_snapshots_id'), 'stats_snapshots', ['id'], unique=False)
        op.create_index(op.f('ix_stats_snapshots_metric'), 'stats_snapshots', ['metric'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_stats_snapshots_metric'), table_name='stats_snapshots')
    op.drop_index(op.f('ix_stats_snapshots_id'), table_name='stats_snapshots')
    op.drop_table('stats_snapshots')
    for table, index_name, _columns in _COMPOSITE_INDEXES:
        bind = op.get_bind()
        inspector = sa.inspect(bind)
        if not inspector.has_table(table):
            continue
        existing = {idx["name"] for idx in inspector.get_indexes(table)}
        if index_name in existing:
            op.drop_index(index_name, table_name=table)
