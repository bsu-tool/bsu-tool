"""Integration tests for MCP device listing on a real Goodix capture."""

from __future__ import annotations

import pathlib

from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


def test_list_devices_goodix_capture() -> None:
    """Session.list_devices enumerates multiple devices from the Goodix capture."""
    session = Session()
    capture = session.load(_CAPTURE)

    devices = session.list_devices()

    assert capture.metadata.packet_count == 253
    assert len(capture.records) == 253
    assert [device.device_id for device in devices] == ["dev_001_000", "dev_001_001", "dev_001_011"]
    assert [device.packet_count for device in devices] == [8, 78, 167]
    assert devices[1].transfer_types_seen == ("control", "interrupt")
    assert [ep.address for ep in devices[2].endpoints_seen] == ["0x00", "0x01", "0x83"]
    assert devices[2].transfer_types_seen == ("control", "bulk")
    assert devices[2].vendor_id == "0x27c6"
    assert devices[2].product_id == "0x63ac"
    assert devices[2].manufacturer == "Goodix Technology Co., Ltd."
    assert devices[2].product == "Goodix Fingerprint USB Device"
