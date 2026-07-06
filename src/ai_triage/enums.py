"""Shared helpers for coercing user-supplied strings into enum members."""

from __future__ import annotations

from enum import Enum
from typing import TypeVar

E = TypeVar("E", bound=Enum)


def coerce_enum(enum_cls: type[E], value: str | None) -> E | None:
    """Return the enum member matching ``value`` (case-insensitive), else ``None``.

    ``None`` and empty strings map to ``None``. Unknown values also map to
    ``None`` so callers can decide how to report the error to the user.
    """
    if value is None or value == "":
        return None
    try:
        return enum_cls(value.lower())
    except ValueError:
        return None
