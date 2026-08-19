"""Tests for the analyze_protocol MCP tool.

The happy paths run the real engine against the Goodix capture and pin values only
a real decode produces, so a stub could not satisfy them. The engine seam is
monkeypatched only where the assertion is about what the tool passes down.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any, cast

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from bsu_tool.analysis.description import ProtocolDescription
from bsu_tool.mcp.server import build_server
from bsu_tool.mcp.tools import analysis
from bsu_tool.session import Capture, Session

_GOODIX = (
    pathlib.Path(__file__).parent.parent.parent.parent
    / "test_data"
    / "captures"
    / "goodix_enum_and_enroll_sanitized.pcapng"
)
# The reader identifies itself by vid:pid; the other device sends no descriptors,
# so it keeps an address-derived id.
_GOODIX_DEVICE_IDS = ("27c6_63ac", "dev_001_001")
_GOODIX_READER = "27c6_63ac"


def _call(tool_arguments: dict[str, Any], session: Session) -> dict[str, Any]:
    """Call analyze_protocol and return its structured, schema-backed output.

    Once a tool carries an output schema FastMCP returns ``(content, structured)``;
    its annotation still describes only the content half, hence the cast.
    """
    result = asyncio.run(build_server(session=session).call_tool("analyze_protocol", tool_arguments))
    _content, structured = cast("tuple[object, dict[str, Any]]", result)
    return structured


def _loaded_session() -> Session:
    session = Session()
    session.load(_GOODIX)
    return session


def test_build_server_registers_analyze_protocol_tool() -> None:
    """build_server registers the Issue #67 analyze_protocol tool."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    assert "analyze_protocol" in asyncio.run(tool_names())


def test_analyze_protocol_without_capture_reports_error() -> None:
    """analyze_protocol fails gracefully when no capture has been loaded."""
    with pytest.raises(ToolError, match="No capture loaded"):
        asyncio.run(build_server(session=Session()).call_tool("analyze_protocol", {}))


def test_analyze_protocol_rejects_unknown_device_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mistyped device_id is reported with the known ids, not silently analyzed as empty."""

    def fake(
        session: Session,
        capture: Capture,
        device_id: str | None,
        *,
        include_command_steps: bool,
        include_observation_steps: bool,
    ) -> tuple[ProtocolDescription, ...]:
        raise AssertionError("the engine must not run for an unknown device_id")

    monkeypatch.setattr(analysis, "_describe", fake)

    with pytest.raises(ToolError, match="unknown device_id 'dev_009_009'"):
        asyncio.run(build_server(session=_loaded_session()).call_tool("analyze_protocol", {"device_id": "dev_009_009"}))


def test_analyze_protocol_forwards_arguments_to_the_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool forwards its arguments untouched, and defers step detail by default.

    The engine selects and reports devices itself, so the tool must not expand
    None into a device list of its own. The two step flags are independent, so a
    caller can pay for one half of the detail without the other.
    """
    seen: list[tuple[str | None, bool, bool]] = []

    def fake(
        session: Session,
        capture: Capture,
        device_id: str | None,
        *,
        include_command_steps: bool,
        include_observation_steps: bool,
    ) -> tuple[ProtocolDescription, ...]:
        del session, capture
        seen.append((device_id, include_command_steps, include_observation_steps))
        return ()

    monkeypatch.setattr(analysis, "_describe", fake)

    _call({}, _loaded_session())
    _call({"device_id": _GOODIX_READER}, _loaded_session())
    _call({"include_command_steps": True}, _loaded_session())
    _call({"include_observation_steps": True}, _loaded_session())

    assert seen == [
        (None, False, False),  # step detail is off unless asked for
        (_GOODIX_READER, False, False),
        (None, True, False),
        (None, False, True),
    ]


def test_analyze_protocol_describes_every_device_by_default() -> None:
    """Omitting device_id runs the real engine over the whole capture."""
    payload = _call({}, _loaded_session())

    described = {entry["device_id"] for entry in payload["descriptions"]}
    assert described == set(_GOODIX_DEVICE_IDS)


def test_analyze_protocol_returns_context_summary_and_findings() -> None:
    """One device_id yields the three things spec 5.12 wants held together.

    Device context, the deterministic summary, and the findings all come back for
    the Goodix reader, pinned to values only a real decode of this capture yields.
    """
    payload = _call({"device_id": _GOODIX_READER}, _loaded_session())

    (description,) = payload["descriptions"]
    assert description["device_id"] == _GOODIX_READER
    # device context, required by spec 1.3 rather than optional enrichment
    assert description["device_summary"]["vendor_id"] == "0x27c6"
    assert description["device_summary"]["product_id"] == "0x63ac"
    assert "Goodix" in description["headline"]
    # the engine's deterministic summary, not prose written by this tool
    assert description["deterministic_summary"].startswith(f"Device {_GOODIX_READER} has 5 repeated command pattern")
    # findings, with the evidence backing them
    assert len(description["commands"]) == 5
    assert description["endpoint_roles"]
    assert description["commands"][0]["evidence"]["first_packet_index"] >= 0
