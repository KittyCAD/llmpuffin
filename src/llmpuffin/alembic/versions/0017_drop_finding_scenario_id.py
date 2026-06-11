"""Drop scenario_id from finding.

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_finding_scenario_id", table_name="finding")
    op.drop_column("finding", "scenario_id")


def downgrade() -> None:
    op.add_column(
        "finding",
        sa.Column("scenario_id", sa.String(128), nullable=False, server_default=""),
    )
    op.create_index("ix_finding_scenario_id", "finding", ["scenario_id"])
