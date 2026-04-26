"""Tests for the SARIF parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_triage.parser import (
    SarifParseError,
    parse_sarif,
    parse_sarif_file,
)


def test_parse_sarif_extracts_findings(sample_sarif_payload: dict) -> None:
    scan = parse_sarif(sample_sarif_payload)

    assert scan.tool_name == "CodeQL"
    assert scan.tool_version == "2.18.0"
    assert scan.raw_run_count == 1
    assert len(scan.findings) == 2

    sql_injection = scan.findings[0]
    assert sql_injection.rule_id == "py/sql-injection"
    assert sql_injection.severity_hint == "high"
    assert sql_injection.tags == ["security", "external/cwe/cwe-089"]
    assert sql_injection.help_uri.startswith("https://")
    assert sql_injection.primary_location is not None
    assert sql_injection.primary_location.file_path == "src/app/db.py"
    assert sql_injection.primary_location.start_line == 42
    assert sql_injection.fingerprint.startswith("py/sql-injection::")


def test_parse_sarif_falls_back_to_level_when_no_security_severity(
    sample_sarif_payload: dict,
) -> None:
    scan = parse_sarif(sample_sarif_payload)
    logging_finding = scan.findings[1]
    # security-severity 5.0 maps to medium.
    assert logging_finding.severity_hint == "medium"
    assert logging_finding.level == "warning"


def test_parse_sarif_file_roundtrip(sample_sarif_file: Path) -> None:
    scan = parse_sarif_file(sample_sarif_file)
    assert len(scan.findings) == 2


def test_parse_sarif_rejects_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "broken.sarif"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SarifParseError):
        parse_sarif_file(bad)


def test_parse_sarif_rejects_missing_runs() -> None:
    with pytest.raises(SarifParseError):
        parse_sarif({"runs": []})

    with pytest.raises(SarifParseError):
        parse_sarif({"version": "2.1.0"})


def test_parse_sarif_skips_results_without_rule_id(sample_sarif_payload: dict) -> None:
    sample_sarif_payload["runs"][0]["results"].append({"message": {"text": "no rule id"}})
    scan = parse_sarif(sample_sarif_payload)
    assert len(scan.findings) == 2  # the malformed entry is skipped


def test_parse_sarif_handles_missing_optional_fields() -> None:
    minimal = {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "py/test",
                        "message": {"text": "hi"},
                    }
                ],
            }
        ]
    }
    scan = parse_sarif(minimal)
    assert scan.findings[0].rule_id == "py/test"
    assert scan.findings[0].primary_location is None
    assert scan.findings[0].fingerprint == "py/test::unknown"


def test_parse_sarif_file_missing_path(tmp_path: Path) -> None:
    with pytest.raises(SarifParseError):
        parse_sarif_file(tmp_path / "missing.sarif")


def test_parse_sarif_uses_security_severity_for_critical() -> None:
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/critical",
                                "properties": {"security-severity": "9.5"},
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/critical",
                        "message": {"text": "boom"},
                    }
                ],
            }
        ]
    }
    scan = parse_sarif(payload)
    assert scan.findings[0].severity_hint == "critical"


def test_parse_sarif_round_trip_via_json_string(sample_sarif_payload: dict) -> None:
    document = json.loads(json.dumps(sample_sarif_payload))
    scan = parse_sarif(document)
    assert len(scan.findings) == 2
