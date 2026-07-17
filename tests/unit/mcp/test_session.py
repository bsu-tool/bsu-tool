"""Tests for the MCP session container."""

import json
import struct
from pathlib import Path
from typing import cast

import pytest

from bsu_tool.mcp.interfaces import EndpointSummary
from bsu_tool.pcapng_reader import PcapNgError
from bsu_tool.session import CaptureSummary, JsonDict, Marker, Session

_USBMON_HEADER_FORMAT = "<QBBBBHBBqiiII8s"
_SUBMISSION = 0x53
_COMPLETION = 0x43
_CONTROL = 2
_BULK = 3
_INTERRUPT = 1
_ISOCHRONOUS = 0


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
    """Session.load keeps metadata while skipping unsupported decoded records.

    Isochronous is the only transfer type still out of scope; interrupt is
    now decoded like control and bulk.
    """
    path = tmp_path / "isochronous.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_ISOCHRONOUS),)))

    capture = Session().load(path)

    assert capture.metadata.packet_count == 1
    assert len(capture.records) == 0
    assert len(capture.transactions) == 0


def test_list_devices_returns_empty_for_unsupported_only_capture(tmp_path: Path) -> None:
    """list_devices returns an empty tuple when no packets decode into records."""
    path = tmp_path / "isochronous-only.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_ISOCHRONOUS),)))
    session = Session()
    session.load(path)

    assert session.list_devices() == ()


def test_load_decodes_interrupt_transfers(tmp_path: Path) -> None:
    """Interrupt transfers are now decoded into records like control and bulk."""
    path = tmp_path / "interrupt.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_INTERRUPT, endpoint=0x81),)))

    capture = Session().load(path)

    assert capture.metadata.packet_count == 1
    assert len(capture.records) == 1
    assert capture.records[0].transfer_type == "interrupt"


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
    assert device_summaries[1].device_class == 0xFF
    assert device_summaries[1].interface_class is None

    serialized_devices = cast(list[JsonDict], capture.to_dict()["devices"])
    assert serialized_devices[1]["device_class"] == 0xFF
    assert serialized_devices[1]["interface_class"] is None


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


def test_get_packets_includes_interrupt(tmp_path: Path) -> None:
    """Interrupt packets appear in the decoded record stream alongside bulk."""
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
    assert selection.total_count == 2
    assert [match.transfer_type for match in selection.matches] == ["bulk", "interrupt"]


def test_get_packet_requires_loaded_capture() -> None:
    """get_packet raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().get_packet(0)


def test_get_packet_returns_record_at_index(tmp_path: Path) -> None:
    """get_packet returns the same PacketRecord get_packets reports at that index."""
    path = tmp_path / "multi.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)

    matches = session.get_packets().matches
    assert len(matches) == 5
    for index, expected in enumerate(matches):
        packet = session.get_packet(index)
        assert packet is not None
        assert packet.index == index
        assert packet == expected


@pytest.mark.parametrize("index", [-1, 5, 100])
def test_get_packet_out_of_range_returns_none(tmp_path: Path, index: int) -> None:
    """get_packet returns None for negative or beyond-the-end indexes (capture has 5)."""
    path = tmp_path / "multi.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)

    assert session.get_packet(index) is None


def test_add_marker_requires_loaded_capture() -> None:
    """add_marker raises RuntimeError if no capture has been loaded."""
    session = Session()
    with pytest.raises(RuntimeError):
        session.add_marker(name="x", packet_index=0)


def test_add_marker_appends_to_capture(tmp_path: Path) -> None:
    """add_marker stores a Marker on the active capture and returns it."""
    session = Session()
    session.load(_write_capture(tmp_path))
    marker = session.add_marker(name="press_button", packet_index=1, note="hi")

    assert isinstance(marker, Marker)
    assert session.capture is not None
    assert session.capture.markers == [marker]
    assert marker.note == "hi"


def test_add_marker_derives_timestamp_from_packet(tmp_path: Path) -> None:
    """The marker's timestamp is the decoded record's timestamp at packet_index."""
    session = Session()
    capture = session.load(_write_capture(tmp_path))

    marker = session.add_marker(name="m", packet_index=1)

    assert marker.timestamp == capture.records[1].timestamp


def test_add_marker_rejects_duplicate_name(tmp_path: Path) -> None:
    """Marker names are unique per capture — duplicates raise ValueError."""
    session = Session()
    session.load(_write_capture(tmp_path))
    session.add_marker(name="press", packet_index=0)

    with pytest.raises(ValueError, match="'press' already exists"):
        session.add_marker(name="press", packet_index=1)


def test_add_marker_rejects_empty_name(tmp_path: Path) -> None:
    """An empty marker name raises ValueError."""
    session = Session()
    session.load(_write_capture(tmp_path))

    with pytest.raises(ValueError, match="must not be empty"):
        session.add_marker(name="", packet_index=0)


@pytest.mark.parametrize("packet_index", [-1, 2, 100])
def test_add_marker_rejects_out_of_range_index(tmp_path: Path, packet_index: int) -> None:
    """packet_index must address a decoded record (capture has 2)."""
    session = Session()
    session.load(_write_capture(tmp_path))

    with pytest.raises(ValueError, match="out of range"):
        session.add_marker(name="m", packet_index=packet_index)


def test_list_markers_requires_loaded_capture() -> None:
    """list_markers raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().list_markers()


def test_list_markers_returns_insertion_order(tmp_path: Path) -> None:
    """list_markers returns () when empty, then markers in the order added."""
    session = Session()
    session.load(_write_capture(tmp_path))

    assert session.list_markers() == ()
    first = session.add_marker(name="a-start", packet_index=0)
    second = session.add_marker(name="a-end", packet_index=1)
    assert session.list_markers() == (first, second)


def _span_session(tmp_path: Path) -> Session:
    """A Session over the 5-packet multi-device capture (indices 0..4)."""
    path = tmp_path / "span.pcapng"
    path.write_bytes(_capture_bytes(_multi_device_packets()))
    session = Session()
    session.load(path)
    return session


def test_packets_between_markers_requires_loaded_capture() -> None:
    """packets_between_markers raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().packets_between_markers("start", "end")


def test_packets_between_markers_returns_packets_strictly_between(tmp_path: Path) -> None:
    """The span is the records between the markers, excluding the marker packets."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=0)
    session.add_marker(name="end", packet_index=4)

    span = session.packets_between_markers("start", "end")

    assert span.start_marker.name == "start"
    assert span.end_marker.name == "end"
    assert span.count == 3
    assert [packet.index for packet in span.packets] == [1, 2, 3]


def test_packets_between_markers_missing_start(tmp_path: Path) -> None:
    """An unknown start marker name raises a clear ValueError."""
    session = _span_session(tmp_path)
    session.add_marker(name="end", packet_index=4)

    with pytest.raises(ValueError, match="no marker named 'start'"):
        session.packets_between_markers("start", "end")


def test_packets_between_markers_missing_end(tmp_path: Path) -> None:
    """An unknown end marker name raises a clear ValueError."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=0)

    with pytest.raises(ValueError, match="no marker named 'end'"):
        session.packets_between_markers("start", "end")


def test_packets_between_markers_rejects_reversed_span(tmp_path: Path) -> None:
    """A start marker anchored after the end marker raises ValueError."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=4)
    session.add_marker(name="end", packet_index=1)

    with pytest.raises(ValueError, match="anchored after"):
        session.packets_between_markers("start", "end")


def test_packets_between_markers_empty_when_adjacent(tmp_path: Path) -> None:
    """Adjacent markers bound no packets, so the span is empty (not an error)."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=2)
    session.add_marker(name="end", packet_index=3)

    span = session.packets_between_markers("start", "end")

    assert span.count == 0
    assert span.packets == ()


def test_packets_between_markers_empty_for_same_name(tmp_path: Path) -> None:
    """Passing one marker name for both ends yields an empty span, not an error."""
    session = _span_session(tmp_path)
    session.add_marker(name="solo", packet_index=2)

    span = session.packets_between_markers("solo", "solo")

    assert span.count == 0
    assert span.packets == ()
    assert span.start_marker is span.end_marker


def test_packets_between_markers_empty_for_distinct_markers_same_index(tmp_path: Path) -> None:
    """Two differently named markers on the same packet bound an empty span."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=2)
    session.add_marker(name="end", packet_index=2)

    span = session.packets_between_markers("start", "end")

    assert span.count == 0
    assert span.packets == ()


def test_packets_between_markers_spans_multiple_devices(tmp_path: Path) -> None:
    """The span filters by index only, so it includes every device in range."""
    session = _span_session(tmp_path)
    # indices 0..4 across two devices: dev_001_004 at 0..1, dev_001_007 at 2..4.
    session.add_marker(name="start", packet_index=0)
    session.add_marker(name="end", packet_index=4)

    span = session.packets_between_markers("start", "end")

    assert [packet.index for packet in span.packets] == [1, 2, 3]
    assert {packet.device_id for packet in span.packets} == {"dev_001_004", "dev_001_007"}


def test_packets_between_markers_filters_by_device(tmp_path: Path) -> None:
    """device_id keeps only that device's packets in the span; count is post-filter."""
    session = _span_session(tmp_path)
    # span 1..3 holds dev_001_004 at index 1 and dev_001_007 at indices 2..3.
    session.add_marker(name="start", packet_index=0)
    session.add_marker(name="end", packet_index=4)

    span = session.packets_between_markers("start", "end", device_id="dev_001_007")

    assert span.count == 2
    assert [packet.index for packet in span.packets] == [2, 3]
    assert {packet.device_id for packet in span.packets} == {"dev_001_007"}


def test_packets_between_markers_device_with_zero_packets_in_span(tmp_path: Path) -> None:
    """A known device absent from the span yields an empty span, not an error."""
    session = _span_session(tmp_path)
    # span 2..3 is all dev_001_007; dev_001_004 exists in the capture but not here.
    session.add_marker(name="start", packet_index=1)
    session.add_marker(name="end", packet_index=4)

    span = session.packets_between_markers("start", "end", device_id="dev_001_004")

    assert span.count == 0
    assert span.packets == ()


def test_packets_between_markers_unknown_device_id_is_empty(tmp_path: Path) -> None:
    """An unknown device_id matches nothing and yields an empty span (as get_packets)."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=0)
    session.add_marker(name="end", packet_index=4)

    span = session.packets_between_markers("start", "end", device_id="dev_009_009")

    assert span.count == 0
    assert span.packets == ()


def test_summary_requires_loaded_capture() -> None:
    """summary raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().summary()


def test_summary_returns_correct_counts(tmp_path: Path) -> None:
    """summary counts devices, packets, markers, and endpoints across devices."""
    setup_device = _get_descriptor_setup(descriptor_type=1, descriptor_index=0, length=18)
    descriptor = _device_descriptor(vendor_id=0x27C6, product_id=0x533C, manufacturer_index=0, product_index=0)
    # Two fully paired devices: dev 4 uses endpoints 0x01/0x81, dev 7 uses 0x00 (control).
    path = tmp_path / "summary.pcapng"
    path.write_bytes(
        _capture_bytes(
            (
                _usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b"a"),
                _usbmon_packet(urb_id=1, event=_COMPLETION, endpoint=0x81, dev_num=4, data=b"bc"),
                _usbmon_packet(urb_id=2, transfer_type=_CONTROL, endpoint=0x80, dev_num=7, setup=setup_device),
                _usbmon_packet(
                    urb_id=2,
                    event=_COMPLETION,
                    transfer_type=_CONTROL,
                    endpoint=0x80,
                    dev_num=7,
                    flag_setup=0x3E,
                    data=descriptor,
                ),
            )
        )
    )
    session = Session()
    session.load(path)
    session.add_marker(name="start", packet_index=0)
    session.add_marker(name="end", packet_index=3)

    summary = session.summary()

    assert summary == CaptureSummary(
        device_count=2,
        packet_count=4,
        marker_count=2,
        endpoint_count=3,
        unmatched_submission_count=0,
        orphan_completion_count=0,
    )
    assert session.validate() == []


def test_validate_requires_loaded_capture() -> None:
    """validate raises RuntimeError if no capture has been loaded."""
    with pytest.raises(RuntimeError):
        Session().validate()


def test_validate_flags_empty_capture(tmp_path: Path) -> None:
    """A capture that decodes no supported records is reported as empty."""
    path = tmp_path / "isochronous-only.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_ISOCHRONOUS),)))
    session = Session()
    session.load(path)

    assert session.validate() == ["capture contains no decoded USB packets"]


def test_summary_counts_unmatched_submission(tmp_path: Path) -> None:
    """An in-flight submission (no completion) is a neutral summary statistic, not a validate fault."""
    path = tmp_path / "orphan-sub.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(urb_id=1, endpoint=0x01, dev_num=4, data=b"a"),)))
    session = Session()
    session.load(path)

    # A lone submission is still a valid capture: captures normally begin/end mid-transaction.
    assert session.validate() == []
    summary = session.summary()
    assert summary.unmatched_submission_count == 1
    assert summary.orphan_completion_count == 0


def test_summary_counts_orphan_completion(tmp_path: Path) -> None:
    """A completion whose submission was never captured is a neutral statistic, not a validate fault."""
    path = tmp_path / "orphan-comp.pcapng"
    completion = _usbmon_packet(urb_id=9, event=_COMPLETION, endpoint=0x81, dev_num=4, data=b"z")
    path.write_bytes(_capture_bytes((completion,)))
    session = Session()
    session.load(path)

    assert session.validate() == []
    summary = session.summary()
    assert summary.orphan_completion_count == 1
    assert summary.unmatched_submission_count == 0


def test_validate_flags_marker_out_of_range(tmp_path: Path) -> None:
    """A marker anchored outside the decoded record range is reported."""
    session = Session()
    capture = session.load(_write_capture(tmp_path))
    # Bypass add_marker's guard to model a dangling marker reference (capture has 2 records).
    capture.markers.append(Marker(name="stale", timestamp=0.0, packet_index=99))

    assert "marker 'stale' references packet index 99 outside the decoded range 0..1" in session.validate()


def test_validate_reports_multiple_faults_in_order(tmp_path: Path) -> None:
    """With both genuine faults present, validate reports empty-capture first, then the dangling marker."""
    path = tmp_path / "empty-with-marker.pcapng"
    path.write_bytes(_capture_bytes((_usbmon_packet(transfer_type=_ISOCHRONOUS),)))
    session = Session()
    capture = session.load(path)
    assert len(capture.records) == 0
    # Bypass add_marker's guard: on a zero-record capture any index dangles.
    capture.markers.append(Marker(name="stale", timestamp=0.0, packet_index=0))

    assert session.validate() == [
        "capture contains no decoded USB packets",
        "marker 'stale' references packet index 0 outside the decoded range 0..-1",
    ]


def test_session_round_trips_json_safe_dict(tmp_path: Path) -> None:
    """Session serialization preserves devices, packets, markers, and summary counts."""
    session = _span_session(tmp_path)
    session.add_marker(name="start", packet_index=0, note="before action")
    session.add_marker(name="end", packet_index=4, note="after action")

    data = session.to_dict()
    loaded = cast(JsonDict, json.loads(json.dumps(data)))
    rebuilt = Session.from_dict(loaded)

    assert rebuilt.to_dict() == data
    assert rebuilt.summary() == session.summary()
    assert rebuilt.list_devices() == session.list_devices()
    assert rebuilt.list_markers() == session.list_markers()
    assert rebuilt.get_packets().matches == session.get_packets().matches

    capture_data = cast(JsonDict, data["capture"])
    devices = cast(list[JsonDict], capture_data["devices"])
    packets = cast(list[JsonDict], capture_data["packets"])
    markers = cast(list[JsonDict], capture_data["markers"])
    assert len(devices) == 2
    assert len(packets) == 5
    assert len(markers) == 2
    assert "device_class" in devices[0]
    assert "interface_class" in devices[0]
    assert capture_data["summary"] == session.summary().to_dict()

    packet = packets[0]
    assert packet["data_hex"] == "61"
    assert packet["data_preview"] == "61"
    assert packet["setup_hex"] is None
