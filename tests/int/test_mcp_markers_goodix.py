"""Integration tests for MCP marker tools on a real Goodix capture."""

from __future__ import annotations

import asyncio
import json
import pathlib
from typing import Any, cast

from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


def test_marker_tools_bracket_pair_end_to_end() -> None:
    """add_marker and list_markers round-trip a bracket pair through the MCP tools."""
    session = Session()
    capture = session.load(_CAPTURE)
    server = build_server(session=session)

    def call(tool: str, arguments: dict[str, object]) -> dict[str, Any]:
        result = asyncio.run(server.call_tool(tool, arguments))
        if isinstance(result, tuple):
            # (content, structured) for tools with an output schema — a shape
            # the SDK's declared return type omits, hence the cast.
            return cast("dict[str, Any]", result[1])
        assert not isinstance(result, dict)
        block = result[0]
        assert isinstance(block, TextContent)
        payload: dict[str, Any] = json.loads(block.text)
        return payload

    added = call("add_marker", {"name": "enroll-1-start", "packet_index": 10, "note": "finger on"})
    assert added["name"] == "enroll-1-start"
    assert added["packet_index"] == 10
    assert added["timestamp"] == capture.records[10].timestamp
    call("add_marker", {"name": "enroll-1-end", "packet_index": 200})

    listed = call("list_markers", {})
    assert listed["count"] == 2
    names = [marker["name"] for marker in listed["markers"]]
    assert names == ["enroll-1-start", "enroll-1-end"]
    assert listed["markers"][0]["note"] == "finger on"
    assert listed["markers"][1]["note"] is None


def test_packets_between_markers_end_to_end() -> None:
    """packets_between_markers returns the traffic bracketed by a marker pair via MCP."""
    session = Session()
    session.load(_CAPTURE)
    server = build_server(session=session)

    def call(tool: str, arguments: dict[str, object]) -> dict[str, Any]:
        result = asyncio.run(server.call_tool(tool, arguments))
        if isinstance(result, tuple):
            return cast("dict[str, Any]", result[1])
        assert not isinstance(result, dict)
        block = result[0]
        assert isinstance(block, TextContent)
        payload: dict[str, Any] = json.loads(block.text)
        return payload

    call("add_marker", {"name": "enroll-1-start", "packet_index": 10})
    call("add_marker", {"name": "enroll-1-end", "packet_index": 200})

    # a wide limit returns the whole span so we can check its shape
    span = call(
        "packets_between_markers",
        {"start_name": "enroll-1-start", "end_name": "enroll-1-end", "limit": 1000},
    )

    assert span["start_marker"]["name"] == "enroll-1-start"
    assert span["end_marker"]["name"] == "enroll-1-end"
    indices = [packet["index"] for packet in span["packets"]]
    # deterministic values for this capture with markers at 10 and 200
    assert span["span_count"] == 189
    assert span["returned_count"] == len(indices)
    assert span["has_more"] is False
    # strictly between: neither marker's own packet is included
    assert min(indices) == 11
    assert max(indices) == 199

    # a small limit pages the same span without dropping the total count
    first_page = call(
        "packets_between_markers",
        {"start_name": "enroll-1-start", "end_name": "enroll-1-end", "limit": 5},
    )
    assert first_page["span_count"] == span["span_count"]
    assert first_page["returned_count"] == 5
    assert first_page["has_more"] is True
    assert [packet["index"] for packet in first_page["packets"]] == indices[:5]
