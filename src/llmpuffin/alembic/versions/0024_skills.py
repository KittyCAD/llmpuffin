"""Add skill and skill_file tables.

Skills are collections of markdown files that the agent can reference.
Stored in the DB so they can be managed via the web UI.

Revision ID: 0024
Revises: 0023
Create Date: 2026-06-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "skill",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("name", sa.String(256), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "skill_file",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "skill_id",
            sa.BigInteger,
            sa.ForeignKey("skill.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.UniqueConstraint("skill_id", "path"),
    )


def downgrade() -> None:
    op.drop_table("skill_file")
    op.drop_table("skill")
