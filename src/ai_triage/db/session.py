"""Engine and session helpers for SQLAlchemy."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ai_triage.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def init_engine(database_url: str | None = None, *, echo: bool = False) -> Engine:
    """Create the global engine.

    Safe to call multiple times: any previously created engine is disposed
    first so repeated calls do not leak connection pools.
    """
    global _engine, _SessionLocal

    if _engine is not None:
        _engine.dispose()

    url = database_url or get_settings().database_url
    _engine = create_engine(url, echo=echo, pool_pre_ping=True, future=True)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        return init_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        init_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def get_session() -> Session:
    """Return a new SQLAlchemy session bound to the configured engine."""
    return get_session_factory()()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context manager that commits on success and rolls back on error."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine() -> None:
    """Drop the cached engine; primarily used by the test suite."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
