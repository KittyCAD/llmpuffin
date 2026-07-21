"""Add audit_schedule and schedule_run tables.

Revision ID: 0031
Revises: 0030
"""

from alembic import op
import sqlalchemy as sa

revision = "0031"
down_revision = "0030"


def upgrade() -> None:
    op.create_table(
        "audit_schedule",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "profile_id",
            sa.BigInteger,
            sa.ForeignKey("audit_profile.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("cron_expr", sa.String(128), nullable=False),
        sa.Column(
            "enabled", sa.Boolean, nullable=False, server_default="true"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "schedule_run",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "schedule_id",
            sa.BigInteger,
            sa.ForeignKey("audit_schedule.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "audit_run_id",
            sa.BigInteger,
            sa.ForeignKey("audit_run.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="started",
        ),
        sa.Column("error", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("schedule_run")
    op.drop_table("audit_schedule")
