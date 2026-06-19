"""Drop finding.rule_id column.

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-15
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_finding_rule_id", table_name="finding")
    op.drop_column("finding", "rule_id")


def downgrade() -> None:
    op.add_column(
        "finding",
        sa.Column("rule_id", sa.String(128), nullable=False, server_default=""),
    )
    op.create_index("ix_finding_rule_id", "finding", ["rule_id"])
