"""Tests for bsu_tool.status — functional, annotation, and pyright checks."""

import subprocess
import typing

from bsu_tool.status import is_ready


def test_is_ready() -> None:
    """is_ready() should return True."""
    assert is_ready() is True


def test_is_ready_annotated() -> None:
    """is_ready() must have a return type annotation."""
    hints = typing.get_type_hints(is_ready)
    assert "return" in hints, "is_ready() is missing a return type annotation"


def test_pyright_passes() -> None:
    """pyright must exit 0 (no type errors)."""
    result = subprocess.run(
        ["pyright"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout
