"""Tests for the FastAPI dashboard."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ai_triage.dashboard.app import _db_session, app
from ai_triage.db import models, repositories
from ai_triage.parser import parse_sarif


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    def _override() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[_db_session] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(_db_session, None)


@pytest.fixture
def seeded_finding_id(db_session: Session, sample_sarif_payload: dict) -> int:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()
    return scan.findings[0].id


def test_health_returns_200(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_index_returns_200_and_contains_landmarks(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Severity breakdown" in body
    assert "Findings" in body


def test_finding_detail_returns_200_for_existing(
    client: TestClient, seeded_finding_id: int
) -> None:
    response = client.get(f"/findings/{seeded_finding_id}")
    assert response.status_code == 200
    assert "Triage" in response.text


def test_finding_detail_returns_404_for_missing(client: TestClient) -> None:
    response = client.get("/findings/999999")
    assert response.status_code == 404


def test_post_remediation_updates_status_and_redirects(
    client: TestClient, db_session: Session, seeded_finding_id: int
) -> None:
    response = client.post(
        f"/findings/{seeded_finding_id}/remediation",
        data={"status": "fixed", "notes": "Patched in PR 1234."},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith(f"/findings/{seeded_finding_id}")

    refreshed = repositories.get_finding(db_session, seeded_finding_id)
    assert refreshed is not None
    db_session.refresh(refreshed)
    assert refreshed.remediation is not None
    assert refreshed.remediation.status == models.RemediationStatus.FIXED
    assert refreshed.remediation.notes == "Patched in PR 1234."
