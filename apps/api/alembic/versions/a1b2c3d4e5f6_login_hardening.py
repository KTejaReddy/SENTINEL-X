"""login hardening: user lockout columns + login_attempts table

Revision ID: a1b2c3d4e5f6
Revises: 599a70f09149
Create Date: 2026-08-13

Adds `failed_login_count` / `locked_until` to users (progressive account
lockout) and the `login_attempts` table (per-account + per-IP rate limiting
and audit). Both are required by the login hardening layer.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '599a70f09149'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        'login_attempts',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email'])
    op.create_index('ix_login_attempts_ip', 'login_attempts', ['ip'])
    op.create_index('ix_login_attempts_success', 'login_attempts', ['success'])
    op.create_index('ix_login_attempts_created_at', 'login_attempts', ['created_at'])


def downgrade() -> None:
    op.drop_table('login_attempts')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_count')
