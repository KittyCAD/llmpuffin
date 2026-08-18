"""Add choices column to human_question for multiple-choice questions.

Revision ID: 0033
Revises: 0032
"""

from alembic import op
import sqlalchemy as sa

revision = "0033"
down_revision = "0032"


def upgrade() -> None:
    op.add_column("human_question", sa.Column("choices", sa.JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("human_question", "choices")
