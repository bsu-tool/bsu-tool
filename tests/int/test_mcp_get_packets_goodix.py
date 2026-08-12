"""Integration tests for MCP packet retrieval on a real Goodix capture."""

from __future__ import annotations

import asyncio
import json
import pathlib

from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


def test_get_packets_goodix_capture() -> None:
    """Session.get_packets returns decoded packets and filters a multi-device capture."""
    session = Session()
    capture = session.load(_CAPTURE)

    everything = session.get_packets()
    assert everything.total_count == len(capture.records) == 253
    assert len(everything.matches) == 253
    assert [packet.index for packet in everything.matches[:3]] == [0, 1, 2]

    device = session.get_packets(device_id="27c6_63ac")
    assert device.total_count == 253
    assert 0 < len(device.matches) < everything.total_count
    assert {packet.device_id for packet in device.matches} == {"27c6_63ac"}

    bulk_in = session.get_packets(device_id="27c6_63ac", transfer_type="bulk", direction="in")
    assert bulk_in.matches
    for packet in bulk_in.matches:
        assert packet.transfer_type == "bulk"
        assert packet.direction == "in"
        assert packet.endpoint_address == "0x83"

    # Endpoint filters by number: "3" and full address "0x83" both reach EP3 IN
    # once direction is pinned.
    by_number = session.get_packets(device_id="27c6_63ac", endpoint="3", direction="in")
    assert by_number.matches == bulk_in.matches
    assert session.get_packets(device_id="27c6_63ac", endpoint="0x83", direction="in").matches == bulk_in.matches


def test_get_packets_tool_assembles_paginated_result() -> None:
    """The get_packets MCP tool paginates and reports match vs total counts end to end."""
    session = Session()
    session.load(_CAPTURE)
    server = build_server(session=session)

    content = asyncio.run(server.call_tool("get_packets", {"transfer_type": "control", "limit": 5}))
    assert isinstance(content, list)
    block = content[0]
    assert isinstance(block, TextContent)
    payload = json.loads(block.text)

    assert payload["total_count"] == 253
    assert 0 < payload["match_count"] < payload["total_count"]
    assert payload["returned_count"] == 5
    assert payload["limit"] == 5
    assert payload["has_more"] is True
    assert len(payload["packets"]) == 5
    assert all(packet["transfer_type"] == "control" for packet in payload["packets"])
