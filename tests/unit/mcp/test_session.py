"""Tests for the MCP session container."""

from pathlib import Path

import pytest

from bsu_tool.mcp.interfaces import StubPcapReader, StubUrbDecoder
from bsu_tool.mcp.session import Marker, Session


def _new_session() -> Session:
    return Session(reader=StubPcapReader(), decoder=StubUrbDecoder())


def test_load_decodes_every_packet() -> None:
    """Session.load runs every raw packet through the decoder."""
    session = _new_session()
    capture = session.load(Path("ignored"))
    assert len(capture.urbs) == 3
    assert session.capture is capture


def test_load_replaces_previous_capture() -> None:
    """Calling load again replaces the active capture."""
    session = _new_session()
    first = session.load(Path("first"))
    second = session.load(Path("second"))
    assert session.capture is second
    assert second is not first


def test_add_marker_requires_loaded_capture() -> None:
    """add_marker raises RuntimeError if no capture has been loaded."""
    session = _new_session()
    with pytest.raises(RuntimeError):
        session.add_marker(name="x", timestamp=0.0)


def test_add_marker_appends_to_capture() -> None:
    """add_marker stores a Marker on the active capture and returns it."""
    session = _new_session()
    session.load(Path("ignored"))
    marker = session.add_marker(name="press_button", timestamp=0.05, note="hi")
    assert isinstance(marker, Marker)
    assert session.capture is not None
    assert session.capture.markers == [marker]
