"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ai_triage.db.models import Base

os.environ.setdefault("OPENAI_API_KEY", "sk-test")


@pytest.fixture
def sample_sarif_payload() -> dict:
    """Minimal SARIF document with two findings for parser/integration tests."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.18.0",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "name": "SQL injection",
                                "shortDescription": {"text": "User-controlled SQL query."},
                                "helpUri": "https://codeql.github.com/codeql-query-help/python/py-sql-injection",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-089"],
                                    "security-severity": "8.8",
                                },
                            },
                            {
                                "id": "py/clear-text-logging",
                                "name": "Clear text logging",
                                "shortDescription": {"text": "Logs may contain sensitive data."},
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-532"],
                                    "security-severity": "5.0",
                                },
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "User input flows into a SQL query."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app/db.py"},
                                    "region": {
                                        "startLine": 42,
                                        "endLine": 42,
                                        "snippet": {
                                            "text": "db.execute(f'SELECT * FROM users WHERE name={name}')"
                                        },
                                    },
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                    },
                    {
                        "ruleId": "py/clear-text-logging",
                        "level": "warning",
                        "message": {"text": "Sensitive token may be logged."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app/auth.py"},
                                    "region": {"startLine": 17},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }


@pytest.fixture
def sample_sarif_file(tmp_path: Path, sample_sarif_payload: dict) -> Path:
    target = tmp_path / "sample.sarif"
    target.write_text(json.dumps(sample_sarif_payload), encoding="utf-8")
    return target


@pytest.fixture
def db_session(tmp_path: Path) -> Iterator[Session]:
    """Provide an isolated SQLite database for each test."""
    db_path = tmp_path / "test.sqlite"
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(  # noqa: N806 — SessionLocal is the conventional SQLAlchemy name
        bind=engine, autoflush=False, expire_on_commit=False, future=True
    )
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
