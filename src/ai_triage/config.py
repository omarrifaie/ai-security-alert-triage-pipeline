"""Centralised settings loaded from environment variables / .env files."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the triage pipeline."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = Field(
        default="postgresql+psycopg://triage:triage@localhost:5432/triage",
        description="SQLAlchemy connection URL for PostgreSQL.",
    )

    openai_api_key: str = Field(
        default="sk-replace-me",
        description="API key for the OpenAI client used by the triage agent.",
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        description="Model identifier passed to the OpenAI Chat Completions API.",
    )
    openai_timeout_seconds: float = Field(default=30.0)
    openai_max_retries: int = Field(default=3, ge=0, le=10)

    dashboard_host: str = Field(default="0.0.0.0")
    dashboard_port: int = Field(default=8000, ge=1, le=65535)
    dashboard_reload: bool = Field(default=False)

    default_repository: str = Field(default="local/dev")
    log_level: str = Field(default="INFO")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cached Settings; primarily used by the test suite."""
    get_settings.cache_clear()
