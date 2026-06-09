"""constrain finding.severity to low/medium/high/informational

Migrates any existing `critical` severities to `high`, lowercases all values,
and adds a CHECK constraint enforcing the allowed set.

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-20

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


ALLOWED = ("low", "medium", "high", "informational")


def upgrade() -> None:
    # Normalise existing values: lowercase + map `critical` -> `high`.
    op.execute("UPDATE finding SET severity = LOWER(severity)")
    op.execute("UPDATE finding SET severity = 'high' WHERE severity = 'critical'")
    # Any remaining unknown values fall back to 'informational' so the constraint
    # can be applied without aborting.
    op.execute(
        "UPDATE finding SET severity = 'informational' "
        "WHERE severity NOT IN ('low', 'medium', 'high', 'informational')"
    )
    op.create_check_constraint(
        "ck_finding_severity",
        "finding",
        "severity IN ('low', 'medium', 'high', 'informational')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_finding_severity", "finding", type_="check")
