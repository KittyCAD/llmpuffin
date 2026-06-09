"""Add tool_call_id to validation_note.

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "validation_note",
        sa.Column("tool_call_id", sa.String(128), server_default="", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("validation_note", "tool_call_id")
