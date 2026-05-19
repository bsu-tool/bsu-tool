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


def test_capture_session_adds_marker() -> None:
    """CaptureSession can add a marker at a packet index."""
    session = CaptureSession(filepath="/captures/sample.pcapng", devices=[], packet_count=42)

    session.add_marker(name="button_press", packet_index=12)

    assert len(session.markers) == 1
    assert session.markers[0].name == "button_press"
    assert session.markers[0].packet_index == 12
    assert session.markers[0].note == ""


def test_capture_session_adds_marker_with_note() -> None:
    """CaptureSession can add a marker with an optional note."""
    session = CaptureSession(filepath="/captures/sample.pcapng", devices=[], packet_count=42)

    session.add_marker(name="button_press", packet_index=12, note="Pressed relay toggle")

    assert session.markers[0].name == "button_press"
    assert session.markers[0].packet_index == 12
    assert session.markers[0].note == "Pressed relay toggle"


def test_capture_session_adds_multiple_markers() -> None:
    """CaptureSession preserves multiple markers in insertion order."""
    session = CaptureSession(filepath="/captures/sample.pcapng", devices=[], packet_count=42)

    session.add_marker(name="button_press_start", packet_index=12)
    session.add_marker(name="button_press_end", packet_index=18)

    assert len(session.markers) == 2
    assert session.markers[0].name == "button_press_start"
    assert session.markers[0].packet_index == 12
    assert session.markers[1].name == "button_press_end"
    assert session.markers[1].packet_index == 18
