"""Add embedding column to finding.

Uses sentence-transformers all-MiniLM-L6-v2 (384 dimensions).

Revision ID: 0028
Revises: 0027
"""

from alembic import op

revision = "0028"
down_revision = "0027"


def upgrade() -> None:
    op.execute("ALTER TABLE finding ADD COLUMN embedding vector(384)")


def downgrade() -> None:
    op.drop_column("finding", "embedding")
