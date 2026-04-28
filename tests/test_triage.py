"""Tests for the OpenAI triage agent and orchestration."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ai_triage.config import Settings
from ai_triage.db import models, repositories
from ai_triage.parser import parse_sarif
from ai_triage.services import run_triage
from ai_triage.triage import (
    TriageAgent,
    TriageDecision,
    TriageError,
    TriageRequest,
)


def _build_completion(content: str | None) -> SimpleNamespace:
    """Construct a fake OpenAI ChatCompletion response."""
    return SimpleNamespace(
        id="chatcmpl-test",
        model="gpt-test",
        choices=[
            SimpleNamespace(
                index=0,
                finish_reason="stop",
                message=SimpleNamespace(role="assistant", content=content),
            )
        ],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=20, total_tokens=30),
    )


def _settings() -> Settings:
    return Settings(
        openai_api_key="sk-test",
        openai_model="gpt-test",
        openai_max_retries=1,
        openai_timeout_seconds=5.0,
    )


def _make_agent(content: str | None) -> tuple[TriageAgent, MagicMock]:
    fake_completion = _build_completion(content)
    chat_completions = MagicMock()
    chat_completions.create.return_value = fake_completion
    client = SimpleNamespace(chat=SimpleNamespace(completions=chat_completions))
    agent = TriageAgent(client=client, settings=_settings())
    return agent, chat_completions


def test_classify_returns_validated_decision() -> None:
    payload = json.dumps(
        {
            "severity": "high",
            "false_positive_likelihood": 0.1,
            "justification": "Confirmed taint flow from request body to SQL query.",
            "suggested_action": "Use parameterised queries.",
        }
    )
    agent, chat_completions = _make_agent(payload)

    request = TriageRequest(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="User input flows into a SQL query.",
        severity_hint="high",
        file_path="src/app/db.py",
        start_line=42,
        end_line=42,
        snippet="db.execute(f'SELECT * FROM users WHERE name={name}')",
        tags=["security"],
        help_uri=None,
    )

    decision, raw = agent.classify(request)
    assert isinstance(decision, TriageDecision)
    assert decision.severity == models.Severity.HIGH
    assert 0.0 <= decision.false_positive_likelihood <= 1.0
    assert "taint" in decision.justification.lower()
    assert raw["choices"][0]["message"]["content"] == payload

    chat_completions.create.assert_called_once()
    call_kwargs = chat_completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-test"
    assert call_kwargs["response_format"]["type"] == "json_schema"
    assert call_kwargs["temperature"] == 0.0


def test_classify_raises_on_invalid_json() -> None:
    agent, _ = _make_agent("not-json")
    request = TriageRequest(
        rule_id="py/test",
        rule_name="Test",
        message="hi",
        severity_hint="medium",
        file_path=None,
        start_line=None,
        end_line=None,
        snippet=None,
        tags=[],
        help_uri=None,
    )
    with pytest.raises(TriageError):
        agent.classify(request)


def test_classify_raises_on_schema_violation() -> None:
    agent, _ = _make_agent(json.dumps({"severity": "ridiculous", "false_positive_likelihood": 2.0}))
    request = TriageRequest(
        rule_id="py/test",
        rule_name="Test",
        message="hi",
        severity_hint="medium",
        file_path=None,
        start_line=None,
        end_line=None,
        snippet=None,
        tags=[],
        help_uri=None,
    )
    with pytest.raises(TriageError):
        agent.classify(request)


def test_run_triage_persists_results(db_session, sample_sarif_payload) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    payload = json.dumps(
        {
            "severity": "medium",
            "false_positive_likelihood": 0.25,
            "justification": "Likely real but limited blast radius.",
            "suggested_action": "Add input validation.",
        }
    )
    agent, chat_completions = _make_agent(payload)

    summary = run_triage(db_session, agent)

    assert summary.processed == 2
    assert summary.failed == 0
    assert chat_completions.create.call_count == 2

    refreshed = repositories.get_finding(db_session, scan.findings[0].id)
    assert refreshed is not None
    db_session.refresh(refreshed)
    assert refreshed.triage is not None
    assert refreshed.triage.severity == models.Severity.MEDIUM
    assert refreshed.triage.model == "gpt-test"


def test_run_triage_skips_when_no_pending(db_session, sample_sarif_payload) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    for finding in scan.findings:
        repositories.upsert_triage_result(
            db_session,
            finding_id=finding.id,
            severity=models.Severity.LOW,
            false_positive_likelihood=0.5,
            justification="Already triaged.",
            suggested_action=None,
            model="gpt-test",
            raw_response={},
        )
    db_session.commit()

    agent, chat_completions = _make_agent("{}")
    summary = run_triage(db_session, agent)

    assert summary.processed == 0
    assert chat_completions.create.call_count == 0


def test_run_triage_records_failures_without_aborting(db_session, sample_sarif_payload) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()

    chat_completions = MagicMock()
    chat_completions.create.side_effect = [
        _build_completion(
            json.dumps(
                {
                    "severity": "high",
                    "false_positive_likelihood": 0.1,
                    "justification": "Real issue.",
                }
            )
        ),
        _build_completion("not-json"),
    ]
    client = SimpleNamespace(chat=SimpleNamespace(completions=chat_completions))
    agent = TriageAgent(client=client, settings=_settings())

    summary = run_triage(db_session, agent)
    assert summary.processed == 1
    assert summary.failed == 1


def test_run_triage_preserves_partial_progress_on_mid_batch_failure(
    db_session, sample_sarif_payload
) -> None:
    parsed = parse_sarif(sample_sarif_payload)
    scan = repositories.create_scan(db_session, parsed, repository="acme/app")
    db_session.commit()
    first_finding_id = scan.findings[0].id
    second_finding_id = scan.findings[1].id

    chat_completions = MagicMock()
    chat_completions.create.side_effect = [
        _build_completion(
            json.dumps(
                {
                    "severity": "high",
                    "false_positive_likelihood": 0.1,
                    "justification": "Real issue committed before the failure.",
                }
            )
        ),
        _build_completion("not-json"),
    ]
    client = SimpleNamespace(chat=SimpleNamespace(completions=chat_completions))
    agent = TriageAgent(client=client, settings=_settings())

    summary = run_triage(db_session, agent)
    assert summary.processed == 1
    assert summary.failed == 1

    db_session.expire_all()
    first = repositories.get_finding(db_session, first_finding_id)
    assert first is not None
    assert first.triage is not None
    assert first.triage.severity == models.Severity.HIGH

    second = repositories.get_finding(db_session, second_finding_id)
    assert second is not None
    assert second.triage is None


def test_triage_request_to_user_prompt_includes_metadata() -> None:
    request = TriageRequest(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="User input flows.",
        severity_hint="high",
        file_path="src/app/db.py",
        start_line=42,
        end_line=44,
        snippet="db.execute(...)",
        tags=["security", "cwe-089"],
        help_uri="https://example.com",
    )
    prompt = request.to_user_prompt()
    assert "src/app/db.py:42-44" in prompt
    assert "security, cwe-089" in prompt
    assert "https://example.com" in prompt
    assert "db.execute(...)" in prompt
