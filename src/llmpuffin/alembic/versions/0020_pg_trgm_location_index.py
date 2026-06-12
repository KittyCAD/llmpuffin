"""Enable pg_trgm and add trigram index on finding_location.file_path.

Revision ID: 0020
Revises: 0019
Create Date: 2026-06-12
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_finding_location_file_path_trgm "
        "ON finding_location USING gin (file_path gin_trgm_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_finding_location_file_path_trgm")
