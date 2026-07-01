"""file coverage tracking

Revision ID: 0026
Revises: 0025
"""

from alembic import op
import sqlalchemy as sa

revision = "0026"
down_revision = "0025"


def upgrade() -> None:
    op.create_table(
        "file_coverage",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.BigInteger,
            sa.ForeignKey("audit_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("access_type", sa.String(32), nullable=False),
        sa.Column("tool_name", sa.String(64), server_default="", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "audit_run_id",
            "file_path",
            "access_type",
            name="uq_file_coverage_run_path_type",
        ),
    )
    op.create_index(
        "ix_file_coverage_audit_run_id",
        "file_coverage",
        ["audit_run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_file_coverage_audit_run_id")
    op.drop_table("file_coverage")
