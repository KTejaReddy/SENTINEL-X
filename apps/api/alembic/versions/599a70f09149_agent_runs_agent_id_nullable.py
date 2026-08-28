"""agent_runs agent_id nullable

Revision ID: 599a70f09149
Revises: a636bfbfbcdf
Create Date: 2026-08-13 11:19:32.448690

The AgentRun model declares agent_id nullable (runs can be recorded without
a named agent, e.g. ad-hoc AI incident analysis). The initial schema shipped
NOT NULL; this migration aligns the database with the model.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '599a70f09149'
down_revision: Union[str, None] = 'a636bfbfbcdf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('agent_runs') as batch_op:
        batch_op.alter_column('agent_id', existing_type=sa.String(length=32), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table('agent_runs') as batch_op:
        batch_op.alter_column('agent_id', existing_type=sa.String(length=32), nullable=False)
