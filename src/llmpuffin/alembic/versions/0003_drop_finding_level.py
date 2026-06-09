"""drop finding.level

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-19

"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("finding", "level")


def downgrade() -> None:
    op.add_column(
        "finding",
        sa.Column(
            "level",
            sa.String(32),
            nullable=False,
            server_default="warning",
        ),
    )
