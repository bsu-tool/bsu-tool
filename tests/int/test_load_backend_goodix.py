"""Integration tests for the real pcap-ng load path end to end (issue #56).

Capture-specific anchors—including packet and record counts, device identity,
and the Goodix vendor ID—ensure that generic non-empty stubs and silent
count-shifting decode regressions fail. Structural assertions additionally
exercise URB pairing, shared-session state, packet-access boundaries, and
captures without enumeration traffic.
"""

from __future__ import annotations

import asyncio
import json
import pathlib

from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.session import Session

_CAPTURES = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures"
_ENUM_AND_ENROLL = _CAPTURES / "goodix_enum_and_enroll_sanitized.pcapng"
_ENROLL_ONLY = _CAPTURES / "goodix_enroll_sanitized.pcapng"


def test_load_populates_session_from_real_capture() -> None:
    """Loading the real Goodix capture populates decoded and derived session state."""
    session = Session()
    capture = session.load(_ENUM_AND_ENROLL)

    # reader + decoder: counts pinned to this capture, so a count-shifting regression fails here
    assert capture.metadata.packet_count == 253
    assert len(capture.packets) == 253
    assert len(capture.records) == 253
    # pairing path exercised: at least one transaction has both a submission and a completion
    assert any(
        transaction.submission is not None and transaction.completion is not None
        for transaction in capture.transactions
    )
    # derived devices: bind capture-specific identity, descriptor, and endpoints to one device
    devices_by_id = {device.device_id: device for device in session.list_devices()}
    goodix = devices_by_id["27c6_63ac"]
    assert goodix.vendor_id == "0x27c6"
    assert goodix.endpoints_seen
    # packet store: valid indexes return a record, both out-of-range branches return None
    assert session.get_packet(0) is not None
    assert session.get_packet(252) is not None
    assert session.get_packet(253) is None
    assert session.get_packet(-1) is None


def test_load_capture_tool_reports_real_metadata() -> None:
    """The load_capture MCP tool loads a real file, reports pinned metadata, and fills the shared Session.

    Every other test drives Session.load directly; this is the only place the
    tool -> session link of the wiring is executed. The retained ``session`` is
    asserted on afterwards: correct metadata alone would not prove the tool
    stored the capture where the other tools read it.
    """
    session = Session()
    server = build_server(session=session)

    content = asyncio.run(server.call_tool("load_capture", {"path": str(_ENUM_AND_ENROLL)}))
    assert isinstance(content, list)
    assert len(content) == 1
    block = content[0]
    assert isinstance(block, TextContent)
    payload = json.loads(block.text)

    assert payload["packet_count"] == 253
    assert pathlib.Path(payload["source"]).resolve() == _ENUM_AND_ENROLL.resolve()
    assert payload["file_size_bytes"] == _ENUM_AND_ENROLL.stat().st_size
    assert payload["capture_duration_seconds"] > 0
    assert len(payload["interfaces_seen"]) == 1

    # the tool must populate the SHARED session, not just answer correctly
    assert session.capture is not None
    assert session.capture.metadata.packet_count == 253
    assert len(session.capture.records) == 253
    devices_by_id = {device.device_id: device for device in session.list_devices()}
    assert devices_by_id["27c6_63ac"].vendor_id == "0x27c6"


def test_load_enroll_only_capture_without_enumeration_traffic() -> None:
    """The enroll-only goodix capture (bulk-only, no descriptors) still populates devices.

    Covers the second file of the issue's goodix_* requirement: with no
    enumeration traffic the device is identified from traffic alone, so
    descriptor-derived fields stay None rather than breaking the load.
    """
    session = Session()
    capture = session.load(_ENROLL_ONLY)

    assert capture.metadata.packet_count == 30
    assert len(capture.records) == 30
    assert {record.transfer_type for record in capture.records} == {"bulk"}
    (device,) = session.list_devices()
    assert device.device_id == "dev_001_003"
    assert device.vendor_id is None
    assert device.endpoints_seen
