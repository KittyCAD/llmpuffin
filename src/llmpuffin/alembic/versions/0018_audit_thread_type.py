"""Drop thread_type from audit_thread (derivable from finding.fork_thread_id).

Revision ID: 0018
Revises: 0017
Create Date: 2026-06-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("audit_thread", "thread_type")


def downgrade() -> None:
    op.add_column(
        "audit_thread",
        sa.Column("thread_type", sa.String(32), nullable=False, server_default="main"),
    )
