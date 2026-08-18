"""Tests for the analyze_protocol MCP tool.

Hypothesis assembly (#66) has not landed, so these cover the layer this tool owns:
registration, precondition checks, device resolution, and passing the engine's
output through. The engine seam is monkeypatched, mirroring how test_server.py
fakes live host enumeration.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any, cast

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from bsu_tool.analysis.models import ProtocolHypothesis, ResultLimits
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
_GOODIX_DEVICE_IDS = ("dev_001_001", "27c6_63ac")
_GOODIX_READER = "27c6_63ac"


def _hypothesis(device_id: str, *, note: str = "synthetic") -> ProtocolHypothesis:
    """Build an empty hypothesis for one device, standing in for engine output."""
    return ProtocolHypothesis(
        device_id=device_id,
        command_patterns=(),
        observations=(),
        unsolicited_responses=(),
        unanswered_commands=(),
        incomplete_transfers=(),
        marker_correlations=(),
        result_limits=ResultLimits(
            max_command_patterns=20,
            max_observations=10,
            max_variable_values_reported=32,
            command_patterns_truncated=False,
            observations_truncated=False,
            truncation_note=None,
        ),
        analysis_notes=(note,),
    )


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

    def fake(capture: Capture, device_id: str | None) -> tuple[ProtocolHypothesis, ...]:
        raise AssertionError("the engine must not run for an unknown device_id")

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    with pytest.raises(ToolError, match="unknown device_id 'dev_009_009'"):
        asyncio.run(build_server(session=_loaded_session()).call_tool("analyze_protocol", {"device_id": "dev_009_009"}))


def test_analyze_protocol_analyzes_every_device_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting device_id asks the engine for every device, mirroring get_packets.

    The engine, not this wrapper, decides which devices come back, so the tool
    passes None straight through and returns whatever it produces.
    """
    seen: list[str | None] = []

    def fake(capture: Capture, device_id: str | None) -> tuple[ProtocolHypothesis, ...]:
        assert capture.metadata.packet_count == 253  # the real loaded capture reaches the engine
        seen.append(device_id)
        return tuple(_hypothesis(known) for known in _GOODIX_DEVICE_IDS)

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    payload = _call({}, _loaded_session())

    assert seen == [None]
    assert [entry["device_id"] for entry in payload["hypotheses"]] == list(_GOODIX_DEVICE_IDS)


def test_analyze_protocol_filters_to_one_device(monkeypatch: pytest.MonkeyPatch) -> None:
    """A known device_id narrows the analysis to that device alone."""
    seen: list[str | None] = []

    def fake(capture: Capture, device_id: str | None) -> tuple[ProtocolHypothesis, ...]:
        del capture
        seen.append(device_id)
        assert device_id is not None
        return (_hypothesis(device_id, note="only this device"),)

    monkeypatch.setattr(analysis, "_generate_hypotheses", fake)

    payload = _call({"device_id": _GOODIX_READER}, _loaded_session())

    assert seen == [_GOODIX_READER]
    assert [entry["device_id"] for entry in payload["hypotheses"]] == [_GOODIX_READER]
    assert payload["hypotheses"][0]["analysis_notes"] == ["only this device"]
    # the engine's full result shape survives serialization, not just the id
    assert payload["hypotheses"][0]["result_limits"]["max_command_patterns"] == 20


def test_analyze_protocol_reports_assembly_not_available() -> None:
    """Until assembly lands the tool says so plainly instead of returning empty findings.

    An empty result would read as "this capture has no protocol"; the error names the
    issues that deliver the missing step.
    """
    with pytest.raises(ToolError, match="no protocol hypothesis assembly is available yet"):
        asyncio.run(build_server(session=_loaded_session()).call_tool("analyze_protocol", {}))
