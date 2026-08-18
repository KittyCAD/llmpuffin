"""Add human_question table for human-in-the-loop interactions.

Revision ID: 0032
Revises: 0031
"""

from alembic import op
import sqlalchemy as sa

revision = "0032"
down_revision = "0031"


def upgrade() -> None:
    op.create_table(
        "human_question",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "thread_id",
            sa.String(64),
            sa.ForeignKey("audit_thread.thread_id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("tool_call_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("question", sa.Text, nullable=False),
        sa.Column("answer", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("answered_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("human_question")
