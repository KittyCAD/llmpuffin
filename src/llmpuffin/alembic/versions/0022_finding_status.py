"""Replace finding.deleted bool with finding.status enum.

Status values: open, fixed, invalid, deleted.
- deleted=false → 'open'
- deleted=true  → 'deleted'

Revision ID: 0022
Revises: 0021
Create Date: 2026-06-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "finding",
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="open",
        ),
    )
    # Migrate existing data.
    op.execute("UPDATE finding SET status = 'deleted' WHERE deleted = true")
    op.execute("UPDATE finding SET status = 'open' WHERE deleted = false")
    op.drop_column("finding", "deleted")
    op.create_check_constraint(
        "ck_finding_status",
        "finding",
        "status IN ('open', 'fixed', 'invalid', 'deleted')",
    )


def downgrade() -> None:
    op.add_column(
        "finding",
        sa.Column("deleted", sa.Boolean, nullable=False, server_default="false"),
    )
    op.execute("UPDATE finding SET deleted = true WHERE status = 'deleted'")
    op.drop_constraint("ck_finding_status", "finding")
    op.drop_column("finding", "status")
