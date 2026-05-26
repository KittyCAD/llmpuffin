"""Add thread_id and tool_call_id to finding_attachment.

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-22
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("finding_attachment", sa.Column("thread_id", sa.String(64), server_default="", nullable=False))
    op.add_column("finding_attachment", sa.Column("tool_call_id", sa.String(128), server_default="", nullable=False))


def downgrade() -> None:
    op.drop_column("finding_attachment", "tool_call_id")
    op.drop_column("finding_attachment", "thread_id")
