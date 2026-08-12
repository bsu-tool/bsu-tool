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
    # The reader occupied address 0 during enumeration and address 11 afterwards;
    # both fold into one vid:pid identity. The unnamed root hub sent no
    # descriptors, so it keeps its address id.
    assert [device.device_id for device in devices] == ["dev_001_001", "27c6_63ac"]
    assert [device.packet_count for device in devices] == [78, 175]
    assert devices[0].transfer_types_seen == ("control", "interrupt")
    assert [ep.address for ep in devices[1].endpoints_seen] == ["0x00", "0x01", "0x83"]
    assert devices[1].transfer_types_seen == ("control", "bulk")
    assert devices[1].vendor_id == "0x27c6"
    assert devices[1].product_id == "0x63ac"
    assert devices[1].manufacturer == "Goodix Technology Co., Ltd."
    assert devices[1].product == "Goodix Fingerprint USB Device"


def test_merged_device_reports_both_addresses() -> None:
    """A device seen at two addresses reports both, with the operational one last."""
    session = Session()
    session.load(_CAPTURE)

    goodix = next(device for device in session.list_devices() if device.device_id == "27c6_63ac")

    assert [(a.bus_num, a.dev_num) for a in goodix.addresses] == [(1, 0), (1, 11)]
    # bus_num/dev_num report the last address held, not the enumeration address.
    assert (goodix.bus_num, goodix.dev_num) == (1, 11)
    assert goodix.identity_source == "descriptors"
