"""Tests for USB capture session data structures."""

from bsu_tool.session import CaptureSession, USBDevice


def test_capture_session_stores_capture_metadata() -> None:
    """CaptureSession stores filepath, devices, endpoints, and packet count."""
    device = USBDevice(bus_num=1, dev_num=7, endpoints=[0, 1, 129])
    session = CaptureSession(
        filepath="/captures/sample.pcapng",
        devices=[device],
        packet_count=42,
    )

    assert session.filepath == "/captures/sample.pcapng"
    assert session.devices == [device]
    assert session.packet_count == 42
    assert session.devices[0].bus_num == 1
    assert session.devices[0].dev_num == 7
    assert session.devices[0].endpoints == [0, 1, 129]
