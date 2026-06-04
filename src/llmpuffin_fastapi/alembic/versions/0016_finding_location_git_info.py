"""Add origin_remote and head to finding_location.

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "finding_location",
        sa.Column("origin_remote", sa.String(512), server_default="", nullable=False),
    )
    op.add_column(
        "finding_location",
        sa.Column("head", sa.String(64), server_default="", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("finding_location", "head")
    op.drop_column("finding_location", "origin_remote")
