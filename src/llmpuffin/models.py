"""SQLAlchemy models for llmpuffin audit data.

Canonical storage for audit runs, findings, and their relationship to threat
model scenarios. The langgraph checkpoint tables (managed by checkpointer
setup()) live alongside these in the same PostgreSQL database.
"""

from __future__ import annotations

import tomllib
from datetime import datetime

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)

SEVERITY_LEVELS = ("low", "medium", "high", "informational")


class Base(DeclarativeBase):
    pass


class AuditProfile(Base):
    """A reusable audit configuration (profile TOML stored in DB).

    Defines what image to audit, which threat model to use, and how the
    agent should behave. Runs are created from profiles.
    """

    __tablename__ = "audit_profile"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    profile_toml: Mapped[str] = mapped_column(Text)
    jit: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    runs: Mapped[list[AuditRun]] = relationship(
        back_populates="profile", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return self.name

    def parsed_config(self) -> dict:
        return tomllib.loads(self.profile_toml)


class AuditRun(Base):
    """A single execution of the audit harness.

    Currently one thread per run. Resuming reuses the same thread_id
    (langgraph appends to the checkpoint chain).
    """

    __tablename__ = "audit_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_profile.id", ondelete="CASCADE")
    )
    profile_toml: Mapped[str] = mapped_column(Text, default="", server_default="")
    container_image: Mapped[str] = mapped_column(String(512))
    model_name: Mapped[str] = mapped_column(String(128))
    github_repo_url: Mapped[str] = mapped_column(
        String(512), default="", server_default=""
    )
    git_commit: Mapped[str] = mapped_column(String(64), default="", server_default="")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    profile: Mapped[AuditProfile] = relationship(back_populates="runs")
    threads: Mapped[list[AuditThread]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        order_by="AuditThread.created_at",
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        order_by="Finding.created_at.desc()",
    )

    @property
    def status(self) -> str:
        """Derived from thread statuses: running if any thread is running,
        else worst status."""
        statuses = [t.status for t in self.threads]
        if not statuses:
            return "pending"
        if "running" in statuses:
            return "running"
        if "error" in statuses:
            return "error"
        if "recursion_limit" in statuses:
            return "recursion_limit"
        return "completed"

    @property
    def error(self) -> str:
        return "\n".join(t.error for t in self.threads if t.error)

    def __str__(self) -> str:
        threads = ", ".join(t.thread_id for t in self.threads[:3])
        return f"Run {self.id} [{threads}] ({self.status})"

    def github_file_url(
        self, file_path: str, line: int | None = None, end_line: int | None = None
    ) -> str | None:
        base = self.github_repo_url.rstrip("/")
        if not base:
            return None
        ref = self.git_commit or "main"
        clean_path = file_path.lstrip("/")
        if clean_path.startswith("src/"):
            clean_path = clean_path[4:]
        url = f"{base}/blob/{ref}/{clean_path}"
        if line and end_line:
            url += f"#L{line}-L{end_line}"
        elif line:
            url += f"#L{line}"
        return url


class AuditThread(Base):
    """A checkpoint thread belonging to an audit run.

    Each agent invocation (start or resume) creates a new thread.
    """

    __tablename__ = "audit_thread"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_run.id", ondelete="CASCADE")
    )
    thread_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    container_id: Mapped[str] = mapped_column(
        String(128), default="", server_default=""
    )
    status: Mapped[str] = mapped_column(
        String(32), default="running", server_default="running"
    )
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="threads")

    def __str__(self) -> str:
        return self.thread_id


class Finding(Base):
    """A security finding discovered during an audit."""

    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_run.id", ondelete="CASCADE")
    )
    thread_id: Mapped[str] = mapped_column(
        String(64), default="", server_default="", index=True
    )
    local_id: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(512), default="", server_default="")
    scenario_id: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    difficulty: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    exploit_scenario: Mapped[str] = mapped_column(Text)
    recommendations: Mapped[str] = mapped_column(Text)
    validated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    validated_evidence: Mapped[str] = mapped_column(Text, default="", server_default="")
    deleted: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    fork_thread_id: Mapped[str] = mapped_column(
        String(64), default="", server_default="", index=True
    )
    tool_call_id: Mapped[str] = mapped_column(
        String(128), default="", server_default=""
    )
    github_issue_url: Mapped[str] = mapped_column(
        String(512), default="", server_default=""
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="findings")
    locations: Mapped[list[FindingLocation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    attachments: Mapped[list[FindingAttachment]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    validation_notes: Mapped[list[ValidationNote]] = relationship(
        back_populates="finding", cascade="all, delete-orphan",
        order_by="ValidationNote.created_at.desc()",
    )

    __table_args__ = (
        UniqueConstraint(
            "audit_run_id", "local_id", name="uq_finding_audit_run_local_id"
        ),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'informational')",
            name="ck_finding_severity",
        ),
    )

    def __str__(self) -> str:
        return f"{self.rule_id}: {self.title or self.description[:80]}"


class FindingLocation(Base):
    """A source location associated with a finding."""

    __tablename__ = "finding_location"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("finding.id", ondelete="CASCADE")
    )
    file_path: Mapped[str] = mapped_column(String(1024))
    start_line: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="locations")

    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}"


class FindingAttachment(Base):
    """A file exported from the container and attached to a finding."""

    __tablename__ = "finding_attachment"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("finding.id", ondelete="CASCADE")
    )
    filename: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    content: Mapped[bytes] = mapped_column(LargeBinary)
    size: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    thread_id: Mapped[str] = mapped_column(String(64), default="", server_default="")
    tool_call_id: Mapped[str] = mapped_column(String(128), default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    finding: Mapped[Finding] = relationship(back_populates="attachments")


class ValidationNote(Base):
    """An immutable validation note attached to a finding.

    Each call to validate_finding creates a new note. Notes are never
    edited or deleted — they form an append-only evidence log.
    """

    __tablename__ = "validation_note"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("finding.id", ondelete="CASCADE")
    )
    thread_id: Mapped[str] = mapped_column(
        String(64), default="", server_default="", index=True
    )
    tool_call_id: Mapped[str] = mapped_column(
        String(128), default="", server_default=""
    )
    evidence: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    finding: Mapped[Finding] = relationship(back_populates="validation_notes")

    def __str__(self) -> str:
        return self.filename
