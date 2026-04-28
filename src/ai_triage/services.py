"""High-level orchestration helpers used by the CLI and workflows."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from ai_triage.db import models, repositories
from ai_triage.parser import parse_sarif_file
from ai_triage.triage import TriageAgent, TriageError, TriageRequest

logger = logging.getLogger(__name__)


@dataclass
class IngestionReport:
    scan_id: int
    repository: str
    total_findings: int


@dataclass
class TriageSummary:
    processed: int
    failed: int
    skipped: int


def ingest_sarif(
    session: Session,
    sarif_path: str | Path,
    *,
    repository: str,
    commit_sha: str | None = None,
    branch: str | None = None,
) -> IngestionReport:
    """Parse a SARIF file and persist a new ``Scan`` record."""
    parsed = parse_sarif_file(sarif_path)
    scan = repositories.create_scan(
        session,
        parsed,
        repository=repository,
        commit_sha=commit_sha,
        branch=branch,
        sarif_path=str(sarif_path),
    )
    session.commit()
    return IngestionReport(
        scan_id=scan.id,
        repository=scan.repository,
        total_findings=len(parsed.findings),
    )


def run_triage(
    session: Session,
    agent: TriageAgent,
    *,
    limit: int | None = None,
    raise_on_error: bool = False,
) -> TriageSummary:
    """Run the triage agent against every pending finding."""
    findings: list[models.Finding] = list(repositories.list_pending_findings(session, limit=limit))
    total_pending = len(findings)
    processed = 0
    failed = 0

    for finding in findings:
        request = TriageRequest.from_orm(finding)
        try:
            decision, raw_response = agent.classify(request)
            repositories.upsert_triage_result(
                session,
                finding_id=finding.id,
                severity=decision.severity,
                false_positive_likelihood=decision.false_positive_likelihood,
                justification=decision.justification,
                suggested_action=decision.suggested_action,
                model=agent.model,
                raw_response=raw_response,
            )
            session.commit()
            processed += 1
        except TriageError as exc:
            session.rollback()
            logger.warning("Triage failed for finding %s: %s", finding.id, exc)
            failed += 1
            if raise_on_error:
                raise
            continue

    skipped = max(0, total_pending - processed - failed)
    return TriageSummary(processed=processed, failed=failed, skipped=skipped)
