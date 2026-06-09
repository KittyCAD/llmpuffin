"""Add validation_note table and migrate existing validated_evidence.

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "validation_note",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "finding_id",
            sa.BigInteger,
            sa.ForeignKey("finding.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("thread_id", sa.String(64), server_default="", nullable=False),
        sa.Column("evidence", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_validation_note_thread_id", "validation_note", ["thread_id"])

    # Migrate existing validated_evidence into validation_note rows.
    op.execute(
        "INSERT INTO validation_note (finding_id, thread_id, evidence, created_at) "
        "SELECT id, thread_id, validated_evidence, created_at "
        "FROM finding "
        "WHERE validated = true AND validated_evidence != ''"
    )


def downgrade() -> None:
    op.drop_table("validation_note")
