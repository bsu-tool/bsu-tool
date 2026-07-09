"""Integration test: load_capture wires the real pcap-ng backend end to end (issue #56).

Unlike the feature-specific Goodix tests (device enumeration, packet filtering),
this asserts that a single real load populates every session store — reader
output, decoded records and paired transactions, the derived device/endpoint
views, and the packet store's whole-collection and random single-packet access —
so the backend is verified as wired rather than stubbed.
"""

from __future__ import annotations

import pathlib

from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


def test_load_populates_session_from_real_capture() -> None:
    """Loading a real Goodix capture fills every session store, none left empty."""
    session = Session()
    capture = session.load(_CAPTURE)

    # reader → packet store
    assert capture.metadata.packet_count > 0
    assert len(capture.packets) == capture.metadata.packet_count
    # decoder → records + paired transactions
    assert len(capture.records) > 0
    assert len(capture.transactions) > 0
    # derived views: devices, each carrying at least one endpoint
    devices = session.list_devices()
    assert devices
    assert any(device.endpoints_seen for device in devices)
    # packet store: whole-collection and random single-packet access
    assert session.get_packets().total_count == len(capture.records)
    assert session.get_packet(0) is not None
    assert session.get_packet(len(capture.records) - 1) is not None
    assert session.get_packet(len(capture.records)) is None
