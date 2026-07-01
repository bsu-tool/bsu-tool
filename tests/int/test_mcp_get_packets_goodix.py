"""Integration tests for MCP packet retrieval on a real Goodix capture."""

from __future__ import annotations

import pathlib

from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


def test_get_packets_goodix_capture() -> None:
    """Session.get_packets returns decoded packets and filters a multi-device capture."""
    session = Session()
    capture = session.load(_CAPTURE)

    everything = session.get_packets()
    assert everything.total_count == len(capture.records) == 249
    assert len(everything.matches) == 249
    assert [packet.index for packet in everything.matches[:3]] == [0, 1, 2]

    device = session.get_packets(device_id="dev_001_011")
    assert device.total_count == 249
    assert 0 < len(device.matches) < everything.total_count
    assert {packet.device_id for packet in device.matches} == {"dev_001_011"}

    bulk_in = session.get_packets(device_id="dev_001_011", transfer_type="bulk", direction="in")
    assert bulk_in.matches
    for packet in bulk_in.matches:
        assert packet.transfer_type == "bulk"
        assert packet.direction == "in"
        assert packet.endpoint_address == "0x83"
