"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-19

"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_profile",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, unique=True),
        sa.Column("profile_toml", sa.Text(), nullable=False),
        sa.Column("jit", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "audit_run",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "profile_id",
            sa.BigInteger(),
            sa.ForeignKey("audit_profile.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_toml", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column("container_image", sa.String(512), nullable=False),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column(
            "github_repo_url", sa.String(512), nullable=False, server_default=""
        ),
        sa.Column("git_commit", sa.String(64), nullable=False, server_default=""),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "audit_thread",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.BigInteger(),
            sa.ForeignKey("audit_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("thread_id", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "container_id", sa.String(128), nullable=False, server_default=""
        ),
        sa.Column(
            "status", sa.String(32), nullable=False, server_default="running"
        ),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_audit_thread_thread_id", "audit_thread", ["thread_id"])

    op.create_table(
        "finding",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "audit_run_id",
            sa.BigInteger(),
            sa.ForeignKey("audit_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "thread_id", sa.String(64), nullable=False, server_default=""
        ),
        sa.Column("local_id", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False, server_default=""),
        sa.Column("scenario_id", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("difficulty", sa.String(32), nullable=False),
        sa.Column("level", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("recommendations", sa.Text(), nullable=False),
        sa.Column(
            "validated", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "validated_evidence", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column(
            "deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "fork_thread_id", sa.String(64), nullable=False, server_default=""
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_finding_thread_id", "finding", ["thread_id"])
    op.create_index("ix_finding_rule_id", "finding", ["rule_id"])
    op.create_index("ix_finding_scenario_id", "finding", ["scenario_id"])
    op.create_index("ix_finding_fork_thread_id", "finding", ["fork_thread_id"])
    op.create_index(
        "ix_finding_audit_run_local_id", "finding", ["audit_run_id", "local_id"]
    )

    op.create_table(
        "finding_location",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.BigInteger(),
            sa.ForeignKey("finding.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("end_line", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("finding_location")
    op.drop_index("ix_finding_audit_run_local_id", table_name="finding")
    op.drop_index("ix_finding_fork_thread_id", table_name="finding")
    op.drop_index("ix_finding_scenario_id", table_name="finding")
    op.drop_index("ix_finding_rule_id", table_name="finding")
    op.drop_index("ix_finding_thread_id", table_name="finding")
    op.drop_table("finding")
    op.drop_index("ix_audit_thread_thread_id", table_name="audit_thread")
    op.drop_table("audit_thread")
    op.drop_table("audit_run")
    op.drop_table("audit_profile")
