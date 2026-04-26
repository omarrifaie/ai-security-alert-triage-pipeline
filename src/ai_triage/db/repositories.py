"""Repository helpers that wrap common SQLAlchemy queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_triage.db.models import (
    Finding,
    Remediation,
    RemediationStatus,
    Scan,
    Severity,
    TriageResult,
)
from ai_triage.parser import ParsedFinding, ParsedScan


def create_scan(
    session: Session,
    parsed: ParsedScan,
    *,
    repository: str,
    commit_sha: str | None = None,
    branch: str | None = None,
    sarif_path: str | None = None,
) -> Scan:
    """Persist a ``ParsedScan`` and all its findings."""
    scan = Scan(
        repository=repository,
        commit_sha=commit_sha,
        branch=branch,
        tool_name=parsed.tool_name,
        tool_version=parsed.tool_version,
        sarif_path=sarif_path,
    )
    session.add(scan)
    session.flush()

    for parsed_finding in parsed.findings:
        finding = _to_finding(scan_id=scan.id, parsed=parsed_finding)
        finding.remediation = Remediation(status=RemediationStatus.OPEN)
        session.add(finding)

    session.flush()
    return scan


def _to_finding(*, scan_id: int, parsed: ParsedFinding) -> Finding:
    primary = parsed.primary_location
    severity = _coerce_severity(parsed.severity_hint)
    return Finding(
        scan_id=scan_id,
        rule_id=parsed.rule_id,
        rule_name=parsed.rule_name,
        message=parsed.message,
        level=parsed.level,
        severity_hint=severity,
        file_path=primary.file_path if primary else None,
        start_line=primary.start_line if primary else None,
        end_line=primary.end_line if primary else None,
        snippet=primary.snippet if primary else None,
        fingerprint=parsed.fingerprint,
        help_uri=parsed.help_uri,
        tags=list(parsed.tags),
        properties=dict(parsed.properties),
    )


def _coerce_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM


def list_pending_findings(session: Session, *, limit: int | None = None) -> list[Finding]:
    """Return findings that have not yet been triaged."""
    stmt = (
        select(Finding)
        .outerjoin(TriageResult, TriageResult.finding_id == Finding.id)
        .where(TriageResult.id.is_(None))
        .order_by(Finding.created_at.asc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return list(session.scalars(stmt))


def upsert_triage_result(
    session: Session,
    *,
    finding_id: int,
    severity: Severity,
    false_positive_likelihood: float,
    justification: str,
    suggested_action: str | None,
    model: str,
    raw_response: dict[str, Any],
) -> TriageResult:
    """Insert or update the triage result for a finding."""
    existing = session.scalars(
        select(TriageResult).where(TriageResult.finding_id == finding_id)
    ).one_or_none()

    if existing is None:
        existing = TriageResult(finding_id=finding_id)
        session.add(existing)

    existing.severity = severity
    existing.false_positive_likelihood = float(false_positive_likelihood)
    existing.justification = justification
    existing.suggested_action = suggested_action
    existing.model = model
    existing.raw_response = raw_response
    session.flush()
    return existing


def list_findings_with_filters(
    session: Session,
    *,
    repository: str | None = None,
    severity: Severity | None = None,
    status: RemediationStatus | None = None,
    rule_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Finding]:
    """Filtered list used by the dashboard."""
    stmt = select(Finding).join(Scan, Scan.id == Finding.scan_id)
    if repository:
        stmt = stmt.where(Scan.repository == repository)
    if severity is not None:
        stmt = stmt.where(Finding.severity_hint == severity)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if status is not None:
        stmt = stmt.join(Remediation, Remediation.finding_id == Finding.id)
        stmt = stmt.where(Remediation.status == status)
    stmt = stmt.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    return list(session.scalars(stmt))


def update_remediation(
    session: Session,
    *,
    finding_id: int,
    status: RemediationStatus,
    notes: str | None = None,
    assignee: str | None = None,
    pull_request_url: str | None = None,
) -> Remediation:
    """Update or create the remediation row for a finding."""
    remediation = session.scalars(
        select(Remediation).where(Remediation.finding_id == finding_id)
    ).one_or_none()

    if remediation is None:
        remediation = Remediation(finding_id=finding_id)
        session.add(remediation)

    remediation.status = status
    if notes is not None:
        remediation.notes = notes
    if assignee is not None:
        remediation.assignee = assignee
    if pull_request_url is not None:
        remediation.pull_request_url = pull_request_url
    session.flush()
    return remediation


def list_recent_scans(session: Session, *, limit: int = 25) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    return list(session.scalars(stmt))


def remediation_summary(session: Session) -> dict[str, int]:
    """Return a count per remediation status across all findings."""
    counts: dict[str, int] = {member.value: 0 for member in RemediationStatus}
    rows: list[Any] = list(
        session.execute(
            select(Remediation.status, _count(Remediation.id)).group_by(Remediation.status)
        ).all()
    )
    for status, count in rows:
        counts[status.value] = count
    return counts


def _count(column: Any) -> Any:
    from sqlalchemy import func

    return func.count(column)


def severity_breakdown(session: Session, *, repository: str | None = None) -> dict[str, int]:
    counts: dict[str, int] = {member.value: 0 for member in Severity}
    stmt = select(Finding.severity_hint, _count(Finding.id)).group_by(Finding.severity_hint)
    if repository:
        stmt = stmt.join(Scan, Scan.id == Finding.scan_id).where(Scan.repository == repository)
    rows = session.execute(stmt).all()
    for severity, count in rows:
        counts[severity.value] = count
    return counts


def get_finding(session: Session, finding_id: int) -> Finding | None:
    return session.get(Finding, finding_id)


def find_finding_by_fingerprint(
    session: Session, *, scan_id: int, fingerprint: str
) -> Finding | None:
    stmt = select(Finding).where(Finding.scan_id == scan_id, Finding.fingerprint == fingerprint)
    return session.scalars(stmt).one_or_none()


def scan_window(
    session: Session,
    *,
    since: datetime | None = None,
    repository: str | None = None,
) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.created_at.desc())
    if repository:
        stmt = stmt.where(Scan.repository == repository)
    if since is not None:
        stmt = stmt.where(Scan.created_at >= since)
    return list(session.scalars(stmt))
