"""Add project table and link audit_profile to project.

Projects group related profiles. Existing profiles are grouped by
name — each distinct profile name becomes a project.

Revision ID: 0030
Revises: 0029
"""

from alembic import op
import sqlalchemy as sa

revision = "0030"
down_revision = "0029"


def upgrade() -> None:
    op.create_table(
        "project",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("name", sa.String(256), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
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

    # Add nullable project_id first
    op.add_column(
        "audit_profile",
        sa.Column("project_id", sa.BigInteger, nullable=True),
    )

    # Create one project per distinct profile name and assign profiles
    conn = op.get_bind()
    names = conn.execute(
        sa.text("SELECT DISTINCT name FROM audit_profile")
    ).scalars().all()
    for name in names:
        conn.execute(
            sa.text("INSERT INTO project (name) VALUES (:name)"),
            {"name": name},
        )
        project_id = conn.execute(
            sa.text("SELECT id FROM project WHERE name = :name"),
            {"name": name},
        ).scalar()
        conn.execute(
            sa.text(
                "UPDATE audit_profile SET project_id = :pid WHERE name = :name"
            ),
            {"pid": project_id, "name": name},
        )

    # Make NOT NULL
    op.alter_column("audit_profile", "project_id", nullable=False)
    op.create_foreign_key(
        "fk_audit_profile_project_id",
        "audit_profile",
        "project",
        ["project_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # Replace unique constraint on name with (project_id, name)
    op.drop_constraint("audit_profile_name_key", "audit_profile", type_="unique")
    op.create_unique_constraint(
        "uq_audit_profile_project_name", "audit_profile", ["project_id", "name"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_audit_profile_project_name", "audit_profile", type_="unique")
    op.create_unique_constraint("audit_profile_name_key", "audit_profile", ["name"])
    op.drop_constraint(
        "fk_audit_profile_project_id", "audit_profile", type_="foreignkey"
    )
    op.drop_column("audit_profile", "project_id")
    op.drop_table("project")