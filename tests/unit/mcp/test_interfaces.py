"""Tests for MCP typed capture models."""

from bsu_tool.mcp.interfaces import CaptureInterface, CaptureMetadata, CapturePacket, DeviceSummary


def test_capture_metadata_contains_load_capture_fields() -> None:
    """CaptureMetadata carries the Issue #15 load_capture result fields."""
    interface = CaptureInterface(
        interface_id=0,
        link_type=189,
        snap_len=65535,
        timestamp_resolution_seconds=0.000001,
    )
    metadata = CaptureMetadata(
        source="/tmp/example.pcapng",
        file_size_bytes=128,
        packet_count=2,
        capture_duration_seconds=0.25,
        interfaces_seen=(interface,),
    )

    assert metadata.source == "/tmp/example.pcapng"
    assert metadata.file_size_bytes == 128
    assert metadata.packet_count == 2
    assert metadata.capture_duration_seconds == 0.25
    assert metadata.interfaces_seen == (interface,)


def test_capture_packet_retains_packet_block_bytes() -> None:
    """CapturePacket stores raw packet bytes without USB semantic decoding."""
    packet = CapturePacket(
        interface_id=0,
        link_type=189,
        pcap_timestamp_seconds=1.0,
        pcap_captured_length=3,
        pcap_original_length=4,
        packet_data=b"abc",
    )

    assert packet.interface_id == 0
    assert packet.link_type == 189
    assert packet.pcap_timestamp_seconds == 1.0
    assert packet.pcap_captured_length == 3
    assert packet.pcap_original_length == 4
    assert packet.packet_data == b"abc"


def test_device_summary_contains_list_devices_fields() -> None:
    """DeviceSummary carries the Issue #16 list_devices result fields."""
    device = DeviceSummary(
        device_id="dev_001_004",
        bus_num=1,
        dev_num=4,
        packet_count=5,
        endpoints_seen=("0x00", "0x81"),
        transfer_types_seen=("control", "bulk"),
        vendor_id="0x27c6",
        product_id="0x533c",
        manufacturer="Goodix",
        product="Fingerprint Reader",
        descriptor_summary="Goodix Fingerprint Reader (0x27c6:0x533c)",
    )

    assert device.bus_num == 1
    assert device.dev_num == 4
    assert device.packet_count == 5
    assert device.endpoints_seen == ("0x00", "0x81")
    assert device.transfer_types_seen == ("control", "bulk")
    assert device.vendor_id == "0x27c6"
