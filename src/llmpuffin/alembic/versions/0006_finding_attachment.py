"""Add finding_attachment table for files exported from containers.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_attachment",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "finding_id",
            sa.BigInteger,
            sa.ForeignKey("finding.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename", sa.String(1024), nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("size", sa.Integer, server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("finding_attachment")
