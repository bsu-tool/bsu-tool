"""Tests for the pcap-ng writer module.

The writer emits pcap-ng *block* structure only; these tests exercise it
two ways:

* **Byte-level** — decode the written bytes by hand to assert exact field
  layout, endianness, and framing invariants (leading == trailing length,
  4-byte alignment).
* **Round-trip** — feed the written bytes back through
  :class:`~bsu_tool.pcapng_reader.PcapNgReader` and assert the parsed
  blocks carry the values we wrote. This is the strongest single check
  that the two layers agree on the wire format.

Like ``test_pcapng_reader``, these tests define their own little-endian
encoders rather than importing the writer's private helpers, so the test
and the code under test can drift apart and be caught.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import pytest

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgReader,
    SectionHeaderBlock,
)
from bsu_tool.pcapng_writer import PcapNgWriter
from bsu_tool.urb_decoder import LINKTYPE_USB_LINUX_MMAPPED

_LE = "little"


# --- Local encoders / decode helpers ---------------------------------------


def _u16(value: int) -> bytes:
    return value.to_bytes(2, _LE)


def _u32(value: int) -> bytes:
    return value.to_bytes(4, _LE)


def _i64(value: int) -> bytes:
    return value.to_bytes(8, _LE, signed=True)


def _decode_block(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode one framed block at ``offset``.

    Returns ``(block_type, body, next_offset)`` and asserts the framing
    invariants every block must satisfy: total length is a multiple of 4,
    and the leading and trailing total-length fields agree.
    """
    block_type = int.from_bytes(data[offset : offset + 4], _LE)
    total_length = int.from_bytes(data[offset + 4 : offset + 8], _LE)
    assert total_length % 4 == 0, "block total length must be 4-byte aligned"
    trailing = int.from_bytes(data[offset + total_length - 4 : offset + total_length], _LE)
    assert trailing == total_length, "leading and trailing total-length must agree"
    body = data[offset + 8 : offset + total_length - 4]
    return block_type, body, offset + total_length


def _write(fn: Callable[[PcapNgWriter], None]) -> bytes:
    """Run ``fn(writer)`` against a fresh BytesIO and return the bytes."""
    stream = io.BytesIO()
    fn(PcapNgWriter(stream))
    return stream.getvalue()


# ---------------------------------------------------------------------------
# Section Header Block
# ---------------------------------------------------------------------------


def test_shb_field_layout() -> None:
    data = _write(lambda w: w.write_section_header())
    block_type, body, end = _decode_block(data)

    assert block_type == 0x0A0D0D0A
    assert end == len(data)  # exactly one block written
    assert body[0:4] == _u32(0x1A2B3C4D)  # byte-order magic
    assert body[4:6] == _u16(1)  # major version
    assert body[6:8] == _u16(0)  # minor version
    assert body[8:16] == _i64(-1)  # section length "unknown"


def test_shb_roundtrips_through_reader() -> None:
    data = _write(lambda w: w.write_section_header())
    (block,) = list(PcapNgReader(io.BytesIO(data)))
    assert isinstance(block, SectionHeaderBlock)
    assert block.byte_order == "little"
    assert block.major_version == 1
    assert block.minor_version == 0
    assert block.section_length == -1


def test_write_section_header_resets_interface_count() -> None:
    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        assert w.interface_count == 2
        w.write_section_header()  # new section
        assert w.interface_count == 0
        assert w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED) == 0

    _write(body)


# ---------------------------------------------------------------------------
# Interface Description Block
# ---------------------------------------------------------------------------


def test_interface_ids_are_assigned_in_registration_order() -> None:
    ids: list[int] = []

    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        ids.append(w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED))
        ids.append(w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED))
        ids.append(w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED))

    _write(body)
    assert ids == [0, 1, 2]


def test_idb_roundtrips_with_link_type_and_snap_len() -> None:
    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED, snap_len=4096)

    data = _write(body)
    blocks = list(PcapNgReader(io.BytesIO(data)))
    idb = next(b for b in blocks if isinstance(b, InterfaceDescriptionBlock))
    assert idb.link_type == LINKTYPE_USB_LINUX_MMAPPED
    assert idb.snap_len == 4096


def test_idb_carries_tsresol_option() -> None:
    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED, tsresol_exponent=6)

    data = _write(body)
    idb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, InterfaceDescriptionBlock))
    tsresol = next(opt for opt in idb.options if opt.code == 9)  # if_tsresol
    assert tsresol.value == bytes([6])


# ---------------------------------------------------------------------------
# Enhanced Packet Block
# ---------------------------------------------------------------------------


def _write_one_epb(
    packet_data: bytes,
    *,
    timestamp_us: int = 0,
    original_length: int | None = None,
) -> bytes:
    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        iface = w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        w.write_enhanced_packet(iface, timestamp_us, packet_data, original_length=original_length)

    return _write(body)


def test_epb_splits_timestamp_into_high_and_low_words() -> None:
    # Chosen so the high and low 32-bit words are distinct and non-zero.
    ts = 0x1_2345_6789
    data = _write_one_epb(b"\xaa\xbb\xcc\xdd", timestamp_us=ts)
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.timestamp_high == 0x1
    assert epb.timestamp_low == 0x23456789
    # And the reader can reassemble the original value.
    assert (epb.timestamp_high << 32) | epb.timestamp_low == ts


@pytest.mark.parametrize("payload_len", [0, 1, 3, 4, 5, 7, 8])
def test_epb_pads_packet_data_to_four_byte_boundary(payload_len: int) -> None:
    payload = bytes(range(payload_len))
    data = _write_one_epb(payload)
    # The whole file must remain 4-byte aligned regardless of payload length.
    assert len(data) % 4 == 0
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.captured_len == payload_len
    assert epb.packet_data == payload


def test_epb_captured_len_defaults_to_payload_length() -> None:
    data = _write_one_epb(b"\x01\x02\x03")
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.captured_len == 3
    assert epb.original_len == 3


def test_epb_honors_explicit_original_length() -> None:
    # Truncated capture: 4 bytes captured, but 100 on the wire.
    data = _write_one_epb(b"\x01\x02\x03\x04", original_length=100)
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.captured_len == 4
    assert epb.original_len == 100


def test_epb_accepts_empty_packet_data() -> None:
    data = _write_one_epb(b"")
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.captured_len == 0
    assert epb.packet_data == b""


def test_epb_references_the_correct_interface_id() -> None:
    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        second = w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        w.write_enhanced_packet(second, 0, b"\x00")

    data = _write(body)
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert epb.interface_id == 1


# ---------------------------------------------------------------------------
# EPB validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", [-1, 0, 1, 5])
def test_write_enhanced_packet_rejects_unregistered_interface(bad_id: int) -> None:
    # No IDBs registered, so every interface_id is invalid.
    writer = PcapNgWriter(io.BytesIO())
    writer.write_section_header()
    with pytest.raises(ValueError, match="not registered"):
        writer.write_enhanced_packet(bad_id, 0, b"\x00")


@pytest.mark.parametrize("bad_ts", [-1, 1 << 64, (1 << 64) + 1])
def test_write_enhanced_packet_rejects_out_of_range_timestamp(bad_ts: int) -> None:
    writer = PcapNgWriter(io.BytesIO())
    writer.write_section_header()
    iface = writer.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
    with pytest.raises(ValueError, match="64-bit range"):
        writer.write_enhanced_packet(iface, bad_ts, b"\x00")


def test_max_valid_timestamp_is_accepted() -> None:
    ts = (1 << 64) - 1
    data = _write_one_epb(b"\x00", timestamp_us=ts)
    epb = next(b for b in PcapNgReader(io.BytesIO(data)) if isinstance(b, EnhancedPacketBlock))
    assert (epb.timestamp_high << 32) | epb.timestamp_low == ts


# ---------------------------------------------------------------------------
# Full-file round-trip
# ---------------------------------------------------------------------------


def test_full_capture_roundtrips_block_for_block() -> None:
    packets = [
        (b"\x53\x00header-a" + b"\xde\xad\xbe\xef", 1_000_000),
        (b"\x43\x00header-b" + b"\x01", 1_500_000),
        (b"\x45\x00header-c", 2_000_000),
    ]

    def body(w: PcapNgWriter) -> None:
        w.write_section_header()
        iface = w.write_interface_description(link_type=LINKTYPE_USB_LINUX_MMAPPED)
        for data, ts in packets:
            w.write_enhanced_packet(iface, ts, data)

    raw = _write(body)
    blocks = list(PcapNgReader(io.BytesIO(raw)))

    assert isinstance(blocks[0], SectionHeaderBlock)
    assert isinstance(blocks[1], InterfaceDescriptionBlock)
    epbs = [b for b in blocks if isinstance(b, EnhancedPacketBlock)]
    assert len(epbs) == len(packets)
    for epb, (data, ts) in zip(epbs, packets, strict=True):
        assert epb.packet_data == data
        assert (epb.timestamp_high << 32) | epb.timestamp_low == ts
