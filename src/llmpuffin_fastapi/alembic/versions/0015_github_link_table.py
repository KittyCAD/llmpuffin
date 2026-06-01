"""Add github_link table, migrate data from finding.github_issue_url.

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "github_link",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "finding_id",
            sa.BigInteger,
            sa.ForeignKey("finding.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("github_type", sa.String(32), nullable=False),
        sa.Column("github_id", sa.String(128), nullable=False),
        sa.Column("github_url", sa.String(512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # Migrate existing data from finding.github_issue_url.
    op.execute(
        """
        INSERT INTO github_link (finding_id, github_type, github_id, github_url)
        SELECT
            id,
            CASE
                WHEN github_issue_url LIKE '%/security/advisories/%' THEN 'advisory'
                ELSE 'issue'
            END,
            CASE
                WHEN github_issue_url LIKE '%/security/advisories/%'
                    THEN substring(github_issue_url FROM '/advisories/([^/]+)/?$')
                ELSE COALESCE(substring(github_issue_url FROM '/issues/([0-9]+)/?$'), '')
            END,
            github_issue_url
        FROM finding
        WHERE github_issue_url != ''
        """
    )

    op.drop_column("finding", "github_issue_url")


def downgrade() -> None:
    op.add_column(
        "finding",
        sa.Column(
            "github_issue_url", sa.String(512), server_default="", nullable=False
        ),
    )
    op.execute(
        """
        UPDATE finding SET github_issue_url = gl.github_url
        FROM github_link gl WHERE gl.finding_id = finding.id
        """
    )
    op.drop_table("github_link")