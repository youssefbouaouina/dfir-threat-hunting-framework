"""initial schema (endpoints, artifacts, detections, detection_runs, hosts)

Revision ID: 4823f807fcd2
Revises:
Create Date: 2026-08-02 04:15:44.889867

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4823f807fcd2'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _bind():
    return op.get_bind()


def upgrade() -> None:
    """Upgrade schema.

    Idempotent on legacy databases: Phase-1 instances created their tables
    via `Base.metadata.create_all`, so this migration must tolerate tables
    that already exist (guarded with has_table) and still add the Phase-2
    columns (`analyzed_at`, `source_run_id`, `agent_batch_id`) and tables
    (`endpoints`) that were introduced later.
    """
    bind = _bind()

    if not bind.dialect.has_table(bind, 'artifacts'):
        op.create_table('artifacts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('os', sa.String(), nullable=False),
        sa.Column('artifact_type', sa.String(), nullable=False),
        sa.Column('collected_at', sa.String(), nullable=False),
        sa.Column('data', sa.Text(), nullable=False),
        sa.Column('ingested_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.Column('processed', sa.Integer(), nullable=True),
        sa.Column('analyzed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source_run_id', sa.Integer(), nullable=True),
        sa.Column('agent_batch_id', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_artifacts_agent_batch_id'), 'artifacts', ['agent_batch_id'], unique=False)
        op.create_index(op.f('ix_artifacts_artifact_type'), 'artifacts', ['artifact_type'], unique=False)
        op.create_index(op.f('ix_artifacts_host'), 'artifacts', ['host'], unique=False)
        op.create_index(op.f('ix_artifacts_id'), 'artifacts', ['id'], unique=False)
        op.create_index(op.f('ix_artifacts_source_run_id'), 'artifacts', ['source_run_id'], unique=False)
    else:
        # Phase-1 instances lack these columns — add them if missing.
        columns = {row[1] for row in bind.execute(sa.text('PRAGMA table_info(artifacts)'))}
        if 'analyzed_at' not in columns:
            op.add_column('artifacts', sa.Column('analyzed_at', sa.DateTime(timezone=True), nullable=True))
        if 'source_run_id' not in columns:
            op.add_column('artifacts', sa.Column('source_run_id', sa.Integer(), nullable=True))
        if 'agent_batch_id' not in columns:
            op.add_column('artifacts', sa.Column('agent_batch_id', sa.String(), nullable=True))

    if not bind.dialect.has_table(bind, 'detection_runs'):
        op.create_table('detection_runs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('trigger', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('host', sa.String(), nullable=True),
        sa.Column('rescan', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('artifacts_scanned', sa.Integer(), nullable=True),
        sa.Column('detections_found', sa.Integer(), nullable=True),
        sa.Column('by_severity', sa.Text(), nullable=True),
        sa.Column('by_technique', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_detection_runs_id'), 'detection_runs', ['id'], unique=False)

    if not bind.dialect.has_table(bind, 'detections'):
        op.create_table('detections',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('rule_id', sa.String(), nullable=False),
        sa.Column('rule_title', sa.String(), nullable=False),
        sa.Column('technique_id', sa.String(), nullable=True),
        sa.Column('technique_name', sa.String(), nullable=True),
        sa.Column('tactic', sa.String(), nullable=True),
        sa.Column('artifact_type', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('matched_data', sa.Text(), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_detections_host'), 'detections', ['host'], unique=False)
        op.create_index(op.f('ix_detections_id'), 'detections', ['id'], unique=False)
        op.create_index(op.f('ix_detections_rule_id'), 'detections', ['rule_id'], unique=False)
        op.create_index(op.f('ix_detections_technique_id'), 'detections', ['technique_id'], unique=False)

    if not bind.dialect.has_table(bind, 'endpoints'):
        op.create_table('endpoints',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(), nullable=False),
        sa.Column('os', sa.String(), nullable=False),
        sa.Column('agent_version', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('enrollment_token_hash', sa.String(), nullable=True),
        sa.Column('config_json', sa.Text(), nullable=True),
        sa.Column('registered_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_endpoints_hostname'), 'endpoints', ['hostname'], unique=True)
        op.create_index(op.f('ix_endpoints_id'), 'endpoints', ['id'], unique=False)

    if not bind.dialect.has_table(bind, 'hosts'):
        op.create_table('hosts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(), nullable=False),
        sa.Column('os', sa.String(), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_hosts_hostname'), 'hosts', ['hostname'], unique=True)
        op.create_index(op.f('ix_hosts_id'), 'hosts', ['id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_hosts_id'), table_name='hosts')
    op.drop_index(op.f('ix_hosts_hostname'), table_name='hosts')
    op.drop_table('hosts')
    op.drop_index(op.f('ix_endpoints_id'), table_name='endpoints')
    op.drop_index(op.f('ix_endpoints_hostname'), table_name='endpoints')
    op.drop_table('endpoints')
    op.drop_index(op.f('ix_detections_technique_id'), table_name='detections')
    op.drop_index(op.f('ix_detections_rule_id'), table_name='detections')
    op.drop_index(op.f('ix_detections_id'), table_name='detections')
    op.drop_index(op.f('ix_detections_host'), table_name='detections')
    op.drop_table('detections')
    op.drop_index(op.f('ix_detection_runs_id'), table_name='detection_runs')
    op.drop_table('detection_runs')
    op.drop_index(op.f('ix_artifacts_source_run_id'), table_name='artifacts')
    op.drop_index(op.f('ix_artifacts_id'), table_name='artifacts')
    op.drop_index(op.f('ix_artifacts_host'), table_name='artifacts')
    op.drop_index(op.f('ix_artifacts_artifact_type'), table_name='artifacts')
    op.drop_index(op.f('ix_artifacts_agent_batch_id'), table_name='artifacts')
    op.drop_table('artifacts')
    # ### end Alembic commands ###
