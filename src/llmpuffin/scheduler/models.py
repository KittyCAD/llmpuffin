"""SQLAlchemy models for scheduled audits."""

from __future__ import annotations

from datetime import datetime

from llmpuffin.models import AuditProfile

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from llmpuffin.models import Base


class AuditSchedule(Base):
    """A cron-like schedule attached to an audit profile."""

    __tablename__ = "audit_schedule"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_profile.id", ondelete="CASCADE"), unique=True
    )
    cron_expr: Mapped[str] = mapped_column(String(128))
    """Standard 5-field cron expression (minute hour dom month dow)."""
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    profile: Mapped[AuditProfile] = relationship()
    runs: Mapped[list[ScheduleRun]] = relationship(
        back_populates="schedule",
        cascade="all, delete-orphan",
        order_by="ScheduleRun.created_at.desc()",
    )


class ScheduleRun(Base):
    """Record of a scheduled audit execution (success or failure)."""

    __tablename__ = "schedule_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("audit_schedule.id", ondelete="CASCADE")
    )
    audit_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("audit_run.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default="started", server_default="started"
    )
    """started, completed, error"""
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    schedule: Mapped[AuditSchedule] = relationship(back_populates="runs")
