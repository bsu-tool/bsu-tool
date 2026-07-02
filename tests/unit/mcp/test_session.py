"""Tests for the MCP session container."""

import struct
from pathlib import Path

import pytest

from bsu_tool.mcp.interfaces import EndpointSummary
from bsu_tool.pcapng_reader import PcapNgError
from bsu_tool.session import Marker, Session

_USBMON_HEADER_FORMAT = "<QBBBBHBBqiiII8s"
_SUBMISSION = 0x53
_COMPLETION = 0x43
_CONTROL = 2
_BULK = 3
_INTERRUPT = 1


def _pad4(data: bytes) -> bytes:
    pad = (-len(data)) & 3
    return data + b"\x00" * pad


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _i64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=True)


def _wrap(block_type: int, body: bytes) -> bytes:
    body = _pad4(body)
    total_length = 4 + 4 + len(body) + 4
    return _u32(block_type) + _u32(total_length) + body + _u32(total_length)


def _build_shb() -> bytes:
    body = b"\x4d\x3c\x2b\x1a" + _u16(1) + _u16(0) + _i64(-1)
    total_length = 4 + 4 + len(body) + 4
    return b"\x0a\x0d\x0d\x0a" + _u32(total_length) + body + _u32(total_length)


def _build_idb(*, link_type: int = 189, snap_len: int = 65535) -> bytes:
    body = _u16(link_type) + _u16(0) + _u32(snap_len)
    return _wrap(0x00000001, body)


def _build_epb(*, timestamp_low: int, packet_data: bytes, interface_id: int = 0) -> bytes:
    body = (
        _u32(interface_id)
        + _u32(0)
        + _u32(timestamp_low)
        + _u32(len(packet_data))
        + _u32(len(packet_data))
        + _pad4(packet_data)
    )
    return _wrap(0x00000006, body)


def _usbmon_packet(
    *,
    urb_id: int = 1,
    event: int = _SUBMISSION,
    transfer_type: int = _BULK,
    endpoint: int = 0x01,
    dev_num: int = 4,
    bus_num: int = 1,
    flag_setup: int = 0,
    setup: bytes = b"\x00" * 8,
    data: bytes = b"",
) -> bytes:
    header = struct.pack(
        _USBMON_HEADER_FORMAT,
        urb_id,
        event,
        transfer_type,
        endpoint,
        dev_num,
        bus_num,
        flag_setup,
        0,
        100,
        0,
        0,
        len(data),
        len(data),
        setup,
    )
    return header + data


def _get_descriptor_setup(descriptor_type: int, descriptor_index: int, length: int) -> bytes:
    return bytes((0x80, 0x06, descriptor_index, descriptor_type, 0x09, 0x04, length & 0xFF, length >> 8))


def _device_descriptor(*, vendor_id: int, product_id: int, manufacturer_index: int, product_index: int) -> bytes:
    return bytes(
        (
            18,
            1,
            0,
            2,
            0xFF,
            0,
            0,
            64,
            vendor_id & 0xFF,
            vendor_id >> 8,
            product_id & 0xFF,
            product_id >> 8,
            0,
            1,
            manufacturer_index,
            product_index,
            0,
            1,
        )
    )


def _string_descriptor(value: str) -> bytes:
    payload = value.encode("utf-16-le")
    return bytes((len(payload) + 2, 3)) + payload


def _capture_bytes(packet_data: tuple[bytes, ...] | None = None) -> bytes:
    if packet_data is None:
        packet_data = (
            _usbmon_packet(event=_SUBMISSION, endpoint=0x01, data=b"a"),
            _usbmon_packet(event=_COMPLETION, endpoint=0x81, data=b"bc"),
        )
    data = _build_shb() + _build_idb(snap_len=64)
    for index, packet in enumerate(packet_data):
        data += _build_epb(timestamp_low=1_000_000 + index * 250_000, packet_data=packet)
    return data


def _write_capture(tmp_path: Path, name: str = "capture.pcapng") -> Path:
    path = tmp_path / name
    path.write_bytes(_capture_bytes())
    return path


def test_load_reads_pcapng_metadata(tmp_path: Path) -> None:
    """Session.load derives metadata from a real pcap-ng file."""
    path = _write_capture(tmp_path)
    session = Session()

    capture = session.load(path)

    assert session.capture is capture
    assert capture.source == path.resolve()
    assert capture.metadata.source == str(path.resolve())
    assert capture.metadata.file_size_bytes == path.stat().st_size
    assert capture.metadata.packet_count == 2
    assert capture.metadata.capture_duration_seconds is not None
    assert abs(capture.metadata.capture_duration_seconds - 0.25) < 0.000001
    assert len(capture.metadata.interfaces_seen) == 1
    assert capture.metadata.interfaces_seen[0].interface_id == 0
    assert capture.metadata.interfaces_seen[0].link_type == 189
    assert capture.metadata.interfaces_seen[0].snap_len == 64
    assert len(capture.packets) == 2
    assert capture.packets[0].link_type == 189
    assert capture.packets[0].packet_data.endswith(b"a")
    assert capture.packets[1].pcap_timestamp_seconds is not None
    assert abs(capture.packets[1].pcap_timestamp_seconds - 1.25) < 0.000001
    assert len(capture.records) == 2
    assert capture.records[0].bus_num == 1
    assert capture.records[0].dev_num == 4
    assert len(capture.transactions) == 1


def test_load_replaces_previous_capture(tmp_path: Path) -> None:
    """Calling load again replaces the active capture."""
    session = Session()
    first = session.load(_write_capture(tmp_path, "first.pcapng"))
    second = session.load(_write_capture(tmp_path, "second.pcapng"))

    assert session.capture is second
    assert second is not first


def test_load_rejects_non_pcapng_suffix(tmp_path: Path) -> None:
    """Session.load validates that the path names a pcap-ng file."""
    path = tmp_path / "capture.pcap"
    path.write_bytes(_capture_bytes())

    with pytest.raises(ValueError):
        Session().load(path)


def test_load_rejects_missing_file(tmp_path: Path) -> None:
    """Session.load raises FileNotFoundError for a missing pcap-ng file."""
    with pytest.raises(FileNotFoundError):
        Session().load(tmp_path / "missing.pcapng")


def test_load_rejects_malformed_pcapng_without_replacing_capture(tmp_path: Path) -> None:
    """Session.load leaves the active capture untouched when parsing fails."""
    session = Session()
    first = session.load(_write_capture(tmp_path, "first.pcapng"))
    malformed = tmp_path / "malformed.pcapng"
    malformed.write_bytes(b"nope")

    with pytest.raises(PcapNgError):
        session.load(malformed)

    assert session.capture is first


def test_load_rejects_packet_with_unknown_interface(tmp_path: Path) -> None:
    """Session.load rejects packet blocks that reference a missing interface."""
    path = tmp_path / "bad-interface.pcapng"
    path.write_bytes(
        _build_shb()
        + _build_idb(snap_len=64)
        + _build_epb(timestamp_low=1_000_000, packet_data=_usbmon_packet(), interface_id=1)
    )

    with pytest.raises(ValueError, match="unknown interface_id 1"):
        Session().load(path)


def test_load_skips_unsupported_transfers(tmp_path: Path) -> None:
    """Session.load keeps metadata while skipping unsupported decoded records."""
    path = tmp_path / "interrupt.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_INTERRUPT),)))

    capture = Session().load(path)

    assert capture.metadata.packet_count == 1
    assert len(capture.records) == 0
    assert len(capture.transactions) == 0


def test_list_devices_returns_empty_for_unsupported_only_capture(tmp_path: Path) -> None:
    """list_devices returns an empty tuple when no packets decode into records."""
    path = tmp_path / "interrupt-only.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_INTERRUPT),)))
    session = Session()
    session.load(path)

    assert session.list_devices() == ()


def test_list_devices_requires_loaded_capture() -> None:
    """list_devices raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().list_devices()


def test_list_devices_summarizes_multiple_devices(tmp_path: Path) -> None:
    """Session.list_devices returns typed summaries for multiple devices."""
    setup_device = _get_descriptor_setup(descriptor_type=1, descriptor_index=0, length=18)
    setup_manufacturer = _get_descriptor_setup(descriptor_type=3, descriptor_index=1, length=255)
    setup_product = _get_descriptor_setup(descriptor_type=3, descriptor_index=2, length=255)
    descriptor = _device_descriptor(vendor_id=0x27C6, product_id=0x533C, manufacturer_index=1, product_index=2)
    path = tmp_path / "multi-device.pcapng"
    path.write_bytes(
        _capture_bytes(
            (
                _usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b"a"),
                _usbmon_packet(urb_id=1, event=_COMPLETION, endpoint=0x81, dev_num=4, data=b"bc"),
                _usbmon_packet(urb_id=2, endpoint=0x02, dev_num=7, data=b"d"),
                _usbmon_packet(urb_id=3, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, setup=setup_device),
                _usbmon_packet(
                    urb_id=3,
                    event=_COMPLETION,
                    transfer_type=_CONTROL,
                    endpoint=0x80,
                    dev_num=7,
                    flag_setup=0x3E,
                    data=descriptor,
                ),
                _usbmon_packet(urb_id=4, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, setup=setup_manufacturer),
                _usbmon_packet(
                    urb_id=4,
                    event=_COMPLETION,
                    transfer_type=_CONTROL,
                    endpoint=0x80,
                    dev_num=7,
                    flag_setup=0x3E,
                    data=_string_descriptor("Goodix"),
                ),
                _usbmon_packet(urb_id=5, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, setup=setup_product),
                _usbmon_packet(
                    urb_id=5,
                    event=_COMPLETION,
                    transfer_type=_CONTROL,
                    endpoint=0x80,
                    dev_num=7,
                    flag_setup=0x3E,
                    data=_string_descriptor("Fingerprint Reader"),
                ),
            )
        )
    )

    session = Session()
    capture = session.load(path)
    device_summaries = session.list_devices()

    assert len(capture.records) == 9
    assert capture.metadata.packet_count == 9
    assert [device.device_id for device in device_summaries] == ["dev_001_004", "dev_001_007"]
    assert device_summaries[0].packet_count == 2
    assert device_summaries[0].endpoints_seen == (
        EndpointSummary(address="0x01", packet_count=1),
        EndpointSummary(address="0x81", packet_count=1),
    )
    assert device_summaries[0].transfer_types_seen == ("bulk",)
    assert device_summaries[1].packet_count == 7
    assert device_summaries[1].endpoints_seen == (
        EndpointSummary(address="0x00", packet_count=6),
        EndpointSummary(address="0x02", packet_count=1),
    )
    assert device_summaries[1].transfer_types_seen == ("control", "bulk")
    assert device_summaries[1].vendor_id == "0x27c6"
    assert device_summaries[1].product_id == "0x533c"
    assert device_summaries[1].manufacturer == "Goodix"
    assert device_summaries[1].product == "Fingerprint Reader"
    assert device_summaries[1].descriptor_summary == "Goodix Fingerprint Reader (0x27c6:0x533c)"


def _multi_device_packets() -> tuple[bytes, ...]:
    return (
        _usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b"a"),
        _usbmon_packet(urb_id=1, event=_COMPLETION, endpoint=0x81, dev_num=4, data=b"bc"),
        _usbmon_packet(
            urb_id=2, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, setup=b"\x80\x06\x00\x01\x00\x00\x12\x00"
        ),
        _usbmon_packet(urb_id=2, event=_COMPLETION, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, data=b"xyz"),
        _usbmon_packet(urb_id=3, endpoint=0x02, dev_num=7, data=b"d"),
    )


def test_get_packets_requires_loaded_capture() -> None:
    """get_packets raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().get_packets()


def test_get_packets_returns_typed_records(tmp_path: Path) -> None:
    """get_packets returns typed PacketRecord objects with decoded fields and previews."""
    path = tmp_path / "packets.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)

    selection = session.get_packets()

    assert selection.total_count == 5
    assert len(selection.matches) == 5
    first = selection.matches[0]
    assert first.index == 0
    assert first.device_id == "dev_001_004"
    assert first.transfer_type == "bulk"
    assert first.direction == "out"
    assert first.endpoint_address == "0x01"
    assert first.endpoint_number == 1
    assert first.event_type == "submission"
    assert first.data_length == 1
    assert first.data_preview == b"a".hex()
    assert first.setup is None
    control = selection.matches[2]
    assert control.transfer_type == "control"
    assert control.endpoint_address == "0x00"
    assert control.setup == b"\x80\x06\x00\x01\x00\x00\x12\x00".hex()


def test_get_packets_empty_data_has_no_preview(tmp_path: Path) -> None:
    """A packet with no captured data reports data_preview None."""
    path = tmp_path / "empty.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b""),)))
    session = Session()
    session.load(path)

    (packet,) = session.get_packets().matches
    assert packet.data_length == 0
    assert packet.data_preview is None


def test_get_packets_filters_by_device(tmp_path: Path) -> None:
    """device_id narrows matches while total_count stays at the full decoded count."""
    path = tmp_path / "multi.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)

    selection = session.get_packets(device_id="dev_001_007")

    assert selection.total_count == 5
    assert len(selection.matches) == 3
    assert {packet.device_id for packet in selection.matches} == {"dev_001_007"}


def test_get_packets_filters_by_endpoint_direction_and_type(tmp_path: Path) -> None:
    """Endpoint, direction, transfer-type, and event filters compose."""
    path = tmp_path / "multi.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)

    # endpoint 1 appears as an OUT submission and an IN completion, so filtering
    # by number matches both; a full address filters by number too; direction narrows.
    assert len(session.get_packets(endpoint="1").matches) == 2
    assert len(session.get_packets(endpoint="0x81").matches) == 2
    in_packet = session.get_packets(endpoint="1", direction="in")
    assert len(in_packet.matches) == 1
    assert in_packet.matches[0].endpoint_address == "0x81"
    out_packet = session.get_packets(endpoint="0x81", direction="out")
    assert len(out_packet.matches) == 1
    assert out_packet.matches[0].endpoint_address == "0x01"
    assert len(session.get_packets(direction="in").matches) == 3
    assert len(session.get_packets(transfer_type="control").matches) == 2
    assert len(session.get_packets(event_type="completion").matches) == 2
    combined = session.get_packets(device_id="dev_001_007", transfer_type="bulk", direction="out")
    assert len(combined.matches) == 1
    assert combined.matches[0].endpoint_address == "0x02"


def test_get_packets_endpoint_number_is_decimal(tmp_path: Path) -> None:
    """endpoint "15" means endpoint 15 (decimal), not 0x15 (=21 -> 5); addresses use 0x."""
    path = tmp_path / "ep15.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(endpoint=0x0F, dev_num=4, data=b"z"),)))
    session = Session()
    session.load(path)

    assert len(session.get_packets(endpoint="15").matches) == 1  # decimal 15 -> endpoint 15
    assert len(session.get_packets(endpoint="0x8f").matches) == 1  # address low nibble = 15
    assert len(session.get_packets(endpoint="5").matches) == 0  # not misparsed as 0x15 -> 5
    for bad in ("zz", "0xzz", "16", "0x1ff"):
        with pytest.raises(ValueError):
            session.get_packets(endpoint=bad)


def test_get_packets_excludes_interrupt(tmp_path: Path) -> None:
    """Interrupt packets never appear in the decoded record stream."""
    path = tmp_path / "interrupt.pcapng"
    path.write_bytes(
        _capture_bytes(
            (
                _usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b"a"),
                _usbmon_packet(urb_id=2, transfer_type=_INTERRUPT, endpoint=0x83, dev_num=4, data=b"z"),
            )
        )
    )
    session = Session()
    session.load(path)

    selection = session.get_packets()
    assert selection.total_count == 1
    assert selection.matches[0].transfer_type == "bulk"


def test_add_marker_requires_loaded_capture() -> None:
    """add_marker raises RuntimeError if no capture has been loaded."""
    session = Session()
    with pytest.raises(RuntimeError):
        session.add_marker(name="x", timestamp=0.0, packet_index=0)


def test_add_marker_appends_to_capture(tmp_path: Path) -> None:
    """add_marker stores a Marker on the active capture and returns it."""
    session = Session()
    session.load(_write_capture(tmp_path))
    marker = session.add_marker(name="press_button", timestamp=0.05, packet_index=1, note="hi")

    assert isinstance(marker, Marker)
    assert session.capture is not None
    assert session.capture.markers == [marker]
