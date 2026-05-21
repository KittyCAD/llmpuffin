"""Change finding_attachment.content from text to bytea.

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE finding_attachment "
        "ALTER COLUMN content TYPE bytea "
        "USING convert_to(content, 'UTF8')"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE finding_attachment "
        "ALTER COLUMN content TYPE text "
        "USING encode(content, 'escape')"
    )
