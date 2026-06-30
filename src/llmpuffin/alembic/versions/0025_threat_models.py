"""Add threat_model and threat_model_file tables.

Threat models are collections of TOML files stored in the DB,
following the same pattern as skills.

Revision ID: 0025
Revises: 0024
Create Date: 2026-06-30
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_model",
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
        "threat_model_file",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "threat_model_id",
            sa.BigInteger,
            sa.ForeignKey("threat_model.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.UniqueConstraint("threat_model_id", "path"),
    )


def downgrade() -> None:
    op.drop_table("threat_model_file")
    op.drop_table("threat_model")
