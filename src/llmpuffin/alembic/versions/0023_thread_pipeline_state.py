"""Add pipeline_state column to audit_thread.

Tracks which harness pipeline step the thread is currently executing
(e.g. cloning, starting, running).

Revision ID: 0023
Revises: 0022
Create Date: 2026-06-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_thread",
        sa.Column("pipeline_state", sa.String(32), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("audit_thread", "pipeline_state")
