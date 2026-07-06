"""PostgreSQL-backed integration test.

The rest of the suite runs against SQLite, which stores enums as plain VARCHARs
and therefore cannot catch value-binding mismatches against a native Postgres
``ENUM`` type. This test performs a round-trip insert against PostgreSQL when
``DATABASE_URL`` points at one (as it does in CI), and skips otherwise. It guards
the ``severity_enum`` binding behaviour that SQLite cannot exercise.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from ai_triage.db import models


def _postgres_engine():
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith(("postgresql://", "postgresql+")):
        pytest.skip("DATABASE_URL is not a PostgreSQL URL; skipping Postgres integration test.")
    engine = create_engine(url, future=True)
    try:
        with engine.connect():
            pass
    except OperationalError as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    return engine


def test_severity_enum_roundtrip_on_postgres() -> None:
    engine = _postgres_engine()
    # Idempotent when the schema already exists (e.g. after ``alembic upgrade head``).
    models.Base.metadata.create_all(engine)

    with Session(engine, future=True) as session:
        scan = models.Scan(repository="pg/integration", tool_name="CodeQL")
        session.add(scan)
        session.flush()

        finding = models.Finding(
            scan_id=scan.id,
            rule_id="py/enum-roundtrip",
            rule_name="Enum roundtrip",
            message="checking enum binding",
            level="error",
            severity_hint=models.Severity.HIGH,
            fingerprint="py/enum-roundtrip::pg",
            tags=[],
            properties={},
        )
        session.add(finding)
        session.flush()

        triage = models.TriageResult(
            finding_id=finding.id,
            severity=models.Severity.CRITICAL,
            false_positive_likelihood=0.2,
            justification="binding must use the lowercase enum values on Postgres",
            model="gpt-test",
            raw_response={},
        )
        session.add(triage)
        # flush() issues the INSERTs; a name-vs-value binding bug fails right here.
        session.flush()

        session.refresh(finding)
        session.refresh(triage)
        assert finding.severity_hint is models.Severity.HIGH
        assert triage.severity is models.Severity.CRITICAL

        # Roll back so the integration test leaves no rows behind.
        session.rollback()
