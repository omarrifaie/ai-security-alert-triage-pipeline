"""SARIF result parser for CodeQL output.

The parser is intentionally permissive: SARIF files produced by CodeQL
have a stable enough shape, but several fields are optional. We extract
the minimal information needed by the triage agent and database layer
and normalise everything into ``ParsedFinding`` instances.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


class SarifParseError(ValueError):
    """Raised when a SARIF document cannot be parsed."""


@dataclass(frozen=True)
class ParsedLocation:
    """Concrete source location for a finding."""

    file_path: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


@dataclass
class ParsedFinding:
    """Normalised representation of a single SARIF result."""

    rule_id: str
    rule_name: str
    message: str
    level: str
    severity_hint: str
    tool: str
    fingerprint: str
    locations: list[ParsedLocation] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    help_uri: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def primary_location(self) -> ParsedLocation | None:
        return self.locations[0] if self.locations else None


@dataclass
class ParsedScan:
    """Top-level container produced by :func:`parse_sarif`."""

    tool_name: str
    tool_version: str | None
    findings: list[ParsedFinding]
    raw_run_count: int


def parse_sarif_file(path: str | Path) -> ParsedScan:
    """Load a SARIF file and parse it."""
    p = Path(path)
    if not p.exists():
        raise SarifParseError(f"SARIF file not found: {p}")
    try:
        document = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SarifParseError(f"Invalid JSON in {p}: {exc}") from exc
    return parse_sarif(document)


def parse_sarif(document: dict[str, Any]) -> ParsedScan:
    """Parse an in-memory SARIF document."""
    if not isinstance(document, dict):
        raise SarifParseError("SARIF document must be a JSON object.")

    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifParseError("SARIF document must contain at least one run.")

    findings: list[ParsedFinding] = []
    tool_name = "unknown"
    tool_version: str | None = None

    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name") or tool_name
        tool_version = driver.get("semanticVersion") or driver.get("version") or tool_version

        rules_index = _index_rules(driver.get("rules") or [])

        for result in run.get("results") or []:
            finding = _parse_result(result, rules_index, tool_name)
            if finding is not None:
                findings.append(finding)

    return ParsedScan(
        tool_name=tool_name,
        tool_version=tool_version,
        findings=findings,
        raw_run_count=len(runs),
    )


def iter_findings(scan: ParsedScan) -> Iterator[ParsedFinding]:
    """Convenience iterator used by the CLI ingestion path."""
    yield from scan.findings


def _index_rules(rules: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            indexed[rule_id] = rule
    return indexed


def _parse_result(
    result: dict[str, Any],
    rules_index: dict[str, dict[str, Any]],
    tool_name: str,
) -> ParsedFinding | None:
    rule_id = result.get("ruleId")
    if not rule_id:
        # CodeQL always emits a ruleId; if missing, the result is malformed.
        return None

    rule = rules_index.get(rule_id, {})

    message = _extract_text(result.get("message"))
    if not message:
        message = _extract_text(rule.get("shortDescription")) or rule_id

    level = (
        result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    ).lower()
    severity_hint = _resolve_severity(rule, level)

    rule_name = rule.get("name") or _extract_text(rule.get("shortDescription")) or rule_id

    tags: list[str] = []
    properties = rule.get("properties") or {}
    raw_tags = properties.get("tags")
    if isinstance(raw_tags, list):
        tags = [t for t in raw_tags if isinstance(t, str)]

    locations = _parse_locations(result.get("locations") or [])
    fingerprint = _build_fingerprint(result, rule_id, locations)

    help_uri: str | None = None
    help_obj = rule.get("helpUri") or rule.get("help")
    if isinstance(help_obj, str):
        help_uri = help_obj
    elif isinstance(help_obj, dict):
        help_uri = help_obj.get("text") or help_obj.get("markdown")

    return ParsedFinding(
        rule_id=rule_id,
        rule_name=rule_name,
        message=message,
        level=level,
        severity_hint=severity_hint,
        tool=tool_name,
        fingerprint=fingerprint,
        locations=locations,
        tags=tags,
        help_uri=help_uri,
        properties={k: v for k, v in properties.items() if k != "tags"},
    )


def _parse_locations(raw_locations: list[dict[str, Any]]) -> list[ParsedLocation]:
    parsed: list[ParsedLocation] = []
    for location in raw_locations:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        region = physical.get("region") or {}
        snippet = (region.get("snippet") or {}).get("text")

        uri = artifact.get("uri")
        if not uri:
            continue

        parsed.append(
            ParsedLocation(
                file_path=uri,
                start_line=region.get("startLine"),
                start_column=region.get("startColumn"),
                end_line=region.get("endLine"),
                end_column=region.get("endColumn"),
                snippet=snippet,
            )
        )
    return parsed


def _resolve_severity(rule: dict[str, Any], level: str) -> str:
    """Use security-severity if available, otherwise fall back to the level."""
    properties = rule.get("properties") or {}
    raw_score = properties.get("security-severity")
    if raw_score is not None:
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    return SEVERITY_MAP.get(level, "medium")


def _build_fingerprint(
    result: dict[str, Any],
    rule_id: str,
    locations: list[ParsedLocation],
) -> str:
    """Stable identifier for de-duplication across scans."""
    fingerprints = result.get("partialFingerprints") or {}
    if isinstance(fingerprints, dict) and fingerprints:
        # Use the first fingerprint deterministically (sorted by key).
        key = sorted(fingerprints.keys())[0]
        return f"{rule_id}::{fingerprints[key]}"

    if locations:
        loc = locations[0]
        return f"{rule_id}::{loc.file_path}:{loc.start_line or 0}:{loc.start_column or 0}"

    return f"{rule_id}::unknown"


def _extract_text(obj: Any) -> str | None:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return obj.get("text") or obj.get("markdown")
    return None
