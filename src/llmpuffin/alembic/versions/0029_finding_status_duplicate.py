"""Add 'duplicate' to finding status constraint.

Revision ID: 0029
Revises: 0028
"""

from alembic import op

revision = "0029"
down_revision = "0028"


def upgrade() -> None:
    op.drop_constraint("ck_finding_status", "finding")
    op.create_check_constraint(
        "ck_finding_status",
        "finding",
        "status IN ('open', 'fixed', 'invalid', 'deleted', 'duplicate')",
    )


def downgrade() -> None:
    op.execute("UPDATE finding SET status = 'deleted' WHERE status = 'duplicate'")
    op.drop_constraint("ck_finding_status", "finding")
    op.create_check_constraint(
        "ck_finding_status",
        "finding",
        "status IN ('open', 'fixed', 'invalid', 'deleted')",
    )
