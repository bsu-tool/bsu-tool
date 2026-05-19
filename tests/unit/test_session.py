"""Tests for USB capture session data structures."""

from bsu_tool.session import CaptureSession, USBDevice


def test_capture_session_stores_capture_metadata() -> None:
    """CaptureSession stores filepath, devices, endpoints, and packet count."""
    endpoints = [
        USBEndpoint(number=0, packet_count=10),
        USBEndpoint(number=1, packet_count=20),
        USBEndpoint(number=129, packet_count=12),
    ]
    
    device = USBDevice(bus_num=1, dev_num=7, endpoints=endpoints)
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
    assert session.devices[0].endpoints == endpoints
