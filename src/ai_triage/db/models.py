"""SQLAlchemy models for scans, findings, triage results, and remediation."""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationStatus(enum.StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    SUPPRESSED = "suppressed"


class Scan(Base):
    """A single ingestion of a SARIF report."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sarif_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Scan id={self.id} repo={self.repository!r} created_at={self.created_at!r}>"


class Finding(Base):
    """A single SARIF result tied to a scan."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
        Index("ix_findings_rule_id", "rule_id"),
        Index("ix_findings_severity_hint", "severity_hint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(512), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    severity_hint: Mapped[Severity] = mapped_column(
        SAEnum(
            Severity,
            name="severity_enum",
            values_callable=lambda enum_cls: [m.value for m in enum_cls],
        ),
        nullable=False,
        default=Severity.MEDIUM,
    )
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    help_uri: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    triage: Mapped[TriageResult | None] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="selectin",
    )
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding id={self.id} rule={self.rule_id!r} severity={self.severity_hint!r}>"


class TriageResult(Base):
    """Output of the AI triage agent for a single finding."""

    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity_enum", create_type=False),
        nullable=False,
    )
    false_positive_likelihood: Mapped[float] = mapped_column(Float, nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    suggested_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_response: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    finding: Mapped[Finding] = relationship(back_populates="triage")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<TriageResult finding_id={self.finding_id} "
            f"severity={self.severity!r} fp={self.false_positive_likelihood:.2f}>"
        )


class Remediation(Base):
    """Tracks the remediation lifecycle of a finding."""

    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    status: Mapped[RemediationStatus] = mapped_column(
        SAEnum(
            RemediationStatus,
            name="remediation_status_enum",
            values_callable=lambda enum_cls: [m.value for m in enum_cls],
        ),
        default=RemediationStatus.OPEN,
        nullable=False,
    )
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    pull_request_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    finding: Mapped[Finding] = relationship(back_populates="remediation")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Remediation finding_id={self.finding_id} status={self.status!r}>"
