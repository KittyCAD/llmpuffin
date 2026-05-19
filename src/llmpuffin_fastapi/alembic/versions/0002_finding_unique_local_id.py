"""unique (audit_run_id, local_id) on finding

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-19

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Renumber duplicate (audit_run_id, local_id) collisions:
    # keep the oldest row at its existing local_id, renumber the rest to
    # fresh ids continuing past the per-run max.
    op.execute(
        """
        WITH ranked AS (
            SELECT
                id,
                audit_run_id,
                local_id,
                ROW_NUMBER() OVER (
                    PARTITION BY audit_run_id, local_id
                    ORDER BY created_at, id
                ) AS rn
            FROM finding
        ),
        run_max AS (
            SELECT audit_run_id, MAX(local_id) AS max_local_id
            FROM finding
            GROUP BY audit_run_id
        ),
        renumbered AS (
            SELECT
                r.id,
                rm.max_local_id
                    + ROW_NUMBER() OVER (
                        PARTITION BY r.audit_run_id
                        ORDER BY r.local_id, r.id
                      ) AS new_local_id
            FROM ranked r
            JOIN run_max rm ON rm.audit_run_id = r.audit_run_id
            WHERE r.rn > 1
        )
        UPDATE finding f
        SET local_id = rn.new_local_id
        FROM renumbered rn
        WHERE f.id = rn.id;
        """
    )

    # Replace the non-unique index with a unique constraint on the same columns.
    op.drop_index("ix_finding_audit_run_local_id", table_name="finding")
    op.create_unique_constraint(
        "uq_finding_audit_run_local_id",
        "finding",
        ["audit_run_id", "local_id"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_finding_audit_run_local_id", "finding", type_="unique")
    op.create_index(
        "ix_finding_audit_run_local_id", "finding", ["audit_run_id", "local_id"]
    )
