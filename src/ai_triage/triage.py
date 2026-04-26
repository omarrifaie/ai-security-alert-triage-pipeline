"""OpenAI powered triage agent.

The agent receives a parsed CodeQL finding and asks an OpenAI model to
return a structured classification covering severity, false-positive
likelihood, and a short justification. We use the chat completions API
with a JSON schema response format so the output can be deserialised
deterministically into ``TriageDecision``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol, cast

from pydantic import BaseModel, Field, ValidationError, field_validator
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ai_triage.config import Settings, get_settings
from ai_triage.db.models import Severity
from ai_triage.parser import ParsedFinding

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = (
    "You are a senior application security engineer triaging static analysis "
    "findings produced by CodeQL. For each finding you receive, classify the "
    "severity, estimate how likely it is to be a false positive, and write a "
    "concise justification. Respond ONLY with JSON that matches the requested "
    "schema. Do not invent code that you did not see."
)


class TriageError(RuntimeError):
    """Raised when the triage agent fails to produce a valid response."""


class TriageDecision(BaseModel):
    """Validated structured output returned by the model."""

    severity: Severity = Field(
        description="Final severity classification after considering exploitability and impact."
    )
    false_positive_likelihood: float = Field(
        ge=0.0,
        le=1.0,
        description="Probability between 0 and 1 that the finding is a false positive.",
    )
    justification: str = Field(
        min_length=1,
        max_length=2000,
        description="Short explanation supporting the severity and false-positive call.",
    )
    suggested_action: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional remediation hint (e.g. parameterised query, escape user input).",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.lower().strip()
        return value


TRIAGE_JSON_SCHEMA: dict[str, Any] = {
    "name": "triage_decision",
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "severity": {
                "type": "string",
                "enum": [member.value for member in Severity],
                "description": "Final severity classification.",
            },
            "false_positive_likelihood": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
            "justification": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2000,
            },
            "suggested_action": {
                "type": "string",
                "maxLength": 2000,
            },
        },
        "required": [
            "severity",
            "false_positive_likelihood",
            "justification",
        ],
    },
    "strict": True,
}


class _ChatCompletions(Protocol):
    def create(self, **kwargs: Any) -> Any: ...


class _ChatNamespace(Protocol):
    completions: _ChatCompletions


class OpenAILike(Protocol):
    """Structural protocol matching the OpenAI client surface we use."""

    chat: _ChatNamespace


@dataclass
class TriageRequest:
    """Input payload assembled from a ``ParsedFinding`` or ORM ``Finding``."""

    rule_id: str
    rule_name: str
    message: str
    severity_hint: str
    file_path: str | None
    start_line: int | None
    end_line: int | None
    snippet: str | None
    tags: list[str]
    help_uri: str | None

    @classmethod
    def from_parsed(cls, finding: ParsedFinding) -> TriageRequest:
        primary = finding.primary_location
        return cls(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            message=finding.message,
            severity_hint=finding.severity_hint,
            file_path=primary.file_path if primary else None,
            start_line=primary.start_line if primary else None,
            end_line=primary.end_line if primary else None,
            snippet=primary.snippet if primary else None,
            tags=list(finding.tags),
            help_uri=finding.help_uri,
        )

    @classmethod
    def from_orm(cls, finding: Any) -> TriageRequest:
        return cls(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            message=finding.message,
            severity_hint=(
                finding.severity_hint.value
                if hasattr(finding.severity_hint, "value")
                else str(finding.severity_hint)
            ),
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            snippet=finding.snippet,
            tags=list(finding.tags or []),
            help_uri=finding.help_uri,
        )

    def to_user_prompt(self) -> str:
        location = "unknown"
        if self.file_path:
            location = self.file_path
            if self.start_line:
                location += f":{self.start_line}"
                if self.end_line and self.end_line != self.start_line:
                    location += f"-{self.end_line}"

        snippet_block = self.snippet or "(no snippet provided)"
        tags_block = ", ".join(self.tags) if self.tags else "(none)"

        return (
            f"Rule ID: {self.rule_id}\n"
            f"Rule name: {self.rule_name}\n"
            f"CodeQL severity hint: {self.severity_hint}\n"
            f"Location: {location}\n"
            f"Tags: {tags_block}\n"
            f"Help URL: {self.help_uri or '(none)'}\n"
            f"Message:\n{self.message}\n\n"
            f"Code snippet:\n{snippet_block}"
        )


class TriageAgent:
    """Wraps an OpenAI client and produces ``TriageDecision`` objects."""

    def __init__(
        self,
        client: OpenAILike | None = None,
        *,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client or self._build_default_client()

    def _build_default_client(self) -> Any:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - optional dependency missing
            raise TriageError("The 'openai' package must be installed to use TriageAgent.") from exc

        return OpenAI(
            api_key=self._settings.openai_api_key,
            timeout=self._settings.openai_timeout_seconds,
        )

    @property
    def model(self) -> str:
        return self._settings.openai_model

    def classify(self, request: TriageRequest) -> tuple[TriageDecision, dict[str, Any]]:
        """Return the parsed decision plus the raw model response payload."""
        raw = self._call_model(request)
        decision = self._parse_response(raw)
        return decision, _serialise_response(raw)

    def _call_model(self, request: TriageRequest) -> Any:
        @retry(
            reraise=True,
            stop=stop_after_attempt(max(1, self._settings.openai_max_retries)),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type(TriageError),
        )
        def _do_call() -> Any:
            try:
                response = self._client.chat.completions.create(
                    model=self._settings.openai_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": request.to_user_prompt()},
                    ],
                    response_format={
                        "type": "json_schema",
                        "json_schema": TRIAGE_JSON_SCHEMA,
                    },
                    temperature=0.0,
                )
            except Exception as exc:  # pragma: no cover - network / SDK errors
                logger.warning("OpenAI request failed: %s", exc)
                raise TriageError(f"OpenAI request failed: {exc}") from exc

            return response

        return _do_call()

    @staticmethod
    def _parse_response(raw: Any) -> TriageDecision:
        try:
            choice = raw.choices[0]
            content = choice.message.content
        except (AttributeError, IndexError, TypeError) as exc:
            raise TriageError(f"Unexpected OpenAI response shape: {raw!r}") from exc

        if isinstance(content, list):
            text_parts = []
            for part in content:
                if isinstance(part, dict):
                    text_parts.append(part.get("text", ""))
                elif hasattr(part, "text"):
                    text_parts.append(getattr(part, "text", "") or "")
                else:
                    text_parts.append(str(part))
            content = "".join(text_parts)

        if not isinstance(content, str) or not content.strip():
            raise TriageError("OpenAI returned an empty content payload.")

        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise TriageError(f"Triage response was not valid JSON: {content!r}") from exc

        try:
            return TriageDecision.model_validate(payload)
        except ValidationError as exc:
            raise TriageError(f"Triage response failed schema validation: {exc}") from exc


def _serialise_response(response: Any) -> dict[str, Any]:
    """Best-effort conversion of the OpenAI SDK response into a plain dict."""
    if isinstance(response, dict):
        return response
    if hasattr(response, "model_dump") and callable(response.model_dump):
        return cast(dict[str, Any], response.model_dump())
    if hasattr(response, "to_dict") and callable(response.to_dict):
        return cast(dict[str, Any], response.to_dict())
    if hasattr(response, "dict") and callable(response.dict):
        return cast(dict[str, Any], response.dict())
    plain = _to_plain(response)
    if isinstance(plain, dict):
        return plain
    return {"value": plain}


def _to_plain(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return {k: _to_plain(v) for k, v in vars(obj).items()}
    return str(obj)
