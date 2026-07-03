"""Shared offset/limit pagination validation for MCP tools."""

from __future__ import annotations

from typing import Final

DEFAULT_LIMIT: Final[int] = 100
MAX_LIMIT: Final[int] = 1000


def validate_pagination(offset: int, limit: int) -> None:
    """Validate the offset/limit arguments common to paginated MCP tools."""
    if offset < 0:
        raise ValueError("offset must be greater than or equal to 0")
    if limit < 1:
        raise ValueError("limit must be greater than or equal to 1")
    if limit > MAX_LIMIT:
        raise ValueError(f"limit must be less than or equal to {MAX_LIMIT}")
