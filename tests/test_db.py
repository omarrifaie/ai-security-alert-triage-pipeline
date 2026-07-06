"""Database layer tests using a SQLite fixture."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ai_triage.db import models, repositories
from ai_triage.parser import parse_sarif


def test_create_scan_persists_findings_and_remediation(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    assert scan.id is not None
    assert scan.repository == "acme/app"
    assert len(scan.findings) == 2

    # Each finding should have an open remediation row created automatically.
    for finding in scan.findings:
        assert finding.remediation is not None
        assert finding.remediation.status == models.RemediationStatus.OPEN


def test_list_pending_findings_excludes_already_triaged(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    pending = repositories.list_pending_findings(db_session)
    assert len(pending) == 2

    repositories.upsert_triage_result(
        db_session,
        finding_id=scan.findings[0].id,
        severity=models.Severity.HIGH,
        false_positive_likelihood=0.05,
        justification="Confirmed taint flow.",
        suggested_action="Use parameterised query.",
        model="gpt-test",
        raw_response={"id": "1"},
    )
    db_session.commit()

    pending_after = repositories.list_pending_findings(db_session)
    assert len(pending_after) == 1
    assert pending_after[0].id == scan.findings[1].id


def test_upsert_triage_result_updates_existing(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    finding_id = scan.findings[0].id

    first = repositories.upsert_triage_result(
        db_session,
        finding_id=finding_id,
        severity=models.Severity.MEDIUM,
        false_positive_likelihood=0.4,
        justification="Initial guess.",
        suggested_action=None,
        model="gpt-test",
        raw_response={},
    )
    db_session.commit()

    second = repositories.upsert_triage_result(
        db_session,
        finding_id=finding_id,
        severity=models.Severity.HIGH,
        false_positive_likelihood=0.05,
        justification="Confirmed after a closer look.",
        suggested_action="Sanitise input.",
        model="gpt-test",
        raw_response={"choices": []},
    )
    db_session.commit()

    assert first.id == second.id
    assert second.severity == models.Severity.HIGH
    assert second.justification.startswith("Confirmed")


def test_update_remediation_creates_or_updates(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    finding_id = scan.findings[0].id
    remediation = repositories.update_remediation(
        db_session,
        finding_id=finding_id,
        status=models.RemediationStatus.IN_PROGRESS,
        notes="Working on a fix",
        assignee="alice",
        pull_request_url="https://github.com/acme/app/pull/12",
    )
    db_session.commit()

    assert remediation.status == models.RemediationStatus.IN_PROGRESS
    assert remediation.assignee == "alice"

    repositories.update_remediation(
        db_session,
        finding_id=finding_id,
        status=models.RemediationStatus.FIXED,
    )
    db_session.commit()

    refreshed = repositories.get_finding(db_session, finding_id)
    assert refreshed is not None
    assert refreshed.remediation is not None
    assert refreshed.remediation.status == models.RemediationStatus.FIXED
    assert refreshed.remediation.assignee == "alice"


def test_list_findings_with_filters(db_session: Session, sample_sarif_payload: dict) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    high_only = repositories.list_findings_with_filters(db_session, severity=models.Severity.HIGH)
    assert len(high_only) == 1
    assert high_only[0].rule_id == "py/sql-injection"

    by_rule = repositories.list_findings_with_filters(db_session, rule_id="py/clear-text-logging")
    assert len(by_rule) == 1


def test_list_findings_with_filters_by_status(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    # Every finding starts with an OPEN remediation row.
    open_findings = repositories.list_findings_with_filters(
        db_session, status=models.RemediationStatus.OPEN
    )
    assert len(open_findings) == 2

    # Move one to FIXED and confirm the Remediation join filters correctly.
    repositories.update_remediation(
        db_session, finding_id=scan.findings[0].id, status=models.RemediationStatus.FIXED
    )
    db_session.commit()

    fixed = repositories.list_findings_with_filters(
        db_session, status=models.RemediationStatus.FIXED
    )
    assert len(fixed) == 1
    assert fixed[0].id == scan.findings[0].id

    still_open = repositories.list_findings_with_filters(
        db_session, status=models.RemediationStatus.OPEN
    )
    assert len(still_open) == 1
    assert still_open[0].id == scan.findings[1].id


def test_severity_breakdown_and_remediation_summary(
    db_session: Session, sample_sarif_payload: dict
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    severity = repositories.severity_breakdown(db_session)
    assert severity["high"] == 1
    assert severity["medium"] == 1

    remediation = repositories.remediation_summary(db_session)
    assert remediation["open"] == 2
    assert remediation["fixed"] == 0
