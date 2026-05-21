"""Add tool_call_id to finding.

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "finding",
        sa.Column("tool_call_id", sa.String(128), server_default="", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("finding", "tool_call_id")
