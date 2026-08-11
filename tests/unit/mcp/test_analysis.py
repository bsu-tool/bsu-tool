"""Tests for the analyze_protocol MCP tool.

The engine is not merged yet (issues #63, #64, #66), so these cover the layer this
tool owns: registration, precondition checks, device resolution, and passing the
engine's output through. The engine seam is monkeypatched, mirroring how
test_server.py fakes live host enumeration.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from typing import Any

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.mcp.tools import analysis
from bsu_tool.session import Capture, JsonDict, Session

_GOODIX = (
    pathlib.Path(__file__).parent.parent.parent.parent
    / "test_data"
    / "captures"
    / "goodix_enum_and_enroll_sanitized.pcapng"
)
_GOODIX_DEVICE_IDS = ("dev_001_000", "dev_001_001", "dev_001_011")


def _call(tool_arguments: dict[str, Any], session: Session) -> dict[str, Any]:
    content = asyncio.run(build_server(session=session).call_tool("analyze_protocol", tool_arguments))
    assert isinstance(content, list)
    block = content[0]
    assert isinstance(block, TextContent)
    payload: dict[str, Any] = json.loads(block.text)
    return payload


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

    def fake(capture: Capture, device_ids: tuple[str, ...]) -> tuple[JsonDict, ...]:
        raise AssertionError("the engine must not run for an unknown device_id")

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    with pytest.raises(ToolError, match="unknown device_id 'dev_009_009'"):
        asyncio.run(build_server(session=_loaded_session()).call_tool("analyze_protocol", {"device_id": "dev_009_009"}))


def test_analyze_protocol_analyzes_every_device_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting device_id analyzes all devices in the capture, mirroring get_packets."""
    seen: list[tuple[str, ...]] = []

    def fake(capture: Capture, device_ids: tuple[str, ...]) -> tuple[JsonDict, ...]:
        assert capture.metadata.packet_count == 253  # the real loaded capture reaches the engine
        seen.append(device_ids)
        return tuple({"device_id": device_id} for device_id in device_ids)

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    payload = _call({}, _loaded_session())

    assert seen == [_GOODIX_DEVICE_IDS]
    assert [entry["device_id"] for entry in payload["hypotheses"]] == list(_GOODIX_DEVICE_IDS)


def test_analyze_protocol_filters_to_one_device(monkeypatch: pytest.MonkeyPatch) -> None:
    """A known device_id narrows the analysis to that device alone."""
    seen: list[tuple[str, ...]] = []

    def fake(capture: Capture, device_ids: tuple[str, ...]) -> tuple[JsonDict, ...]:
        del capture
        seen.append(device_ids)
        return ({"device_id": device_ids[0], "command_patterns": []},)

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    payload = _call({"device_id": "dev_001_011"}, _loaded_session())

    assert seen == [("dev_001_011",)]
    assert payload["hypotheses"] == [{"device_id": "dev_001_011", "command_patterns": []}]


def test_analyze_protocol_reports_engine_not_available() -> None:
    """Until the engine lands the tool says so plainly instead of returning empty findings.

    An empty result would read as "this capture has no protocol"; the error names the
    issues that deliver the engine.
    """
    with pytest.raises(ToolError, match="engine is not available yet"):
        asyncio.run(build_server(session=_loaded_session()).call_tool("analyze_protocol", {}))
