"""Tests for the pcap-ng reader module.

Naming convention: one test file per module or concern.
Name files after the module/feature being tested, not individual functions.

Good: test_pcap_reader.py, test_urb_decoder.py, test_session.py
Bad:  test_parse_block.py, test_single_function.py

These tests build pcap-ng byte streams by hand so the suite does not
depend on any external capture files. Real-capture round-trips belong
in tests/int/ once we have reference captures from the hardware.
"""

from __future__ import annotations

import io
from typing import Literal

import pytest

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    InterfaceStatisticsBlock,
    InvalidBlockError,
    PcapNgReader,
    SectionHeaderBlock,
    SimplePacketBlock,
    TruncatedFileError,
    UnknownBlock,
    UnsupportedVersionError,
)

ByteOrder = Literal["little", "big"]


# --- Construction helpers --------------------------------------------------


def _pad4(data: bytes) -> bytes:
    pad = (-len(data)) & 3
    return data + b"\x00" * pad


def _u16(value: int, order: ByteOrder) -> bytes:
    return value.to_bytes(2, order)


def _u32(value: int, order: ByteOrder) -> bytes:
    return value.to_bytes(4, order)


def _i64(value: int, order: ByteOrder) -> bytes:
    return value.to_bytes(8, order, signed=True)


def _option(code: int, value: bytes, order: ByteOrder) -> bytes:
    return _u16(code, order) + _u16(len(value), order) + _pad4(value)


def _opt_endofopt(order: ByteOrder) -> bytes:
    return _u16(0, order) + _u16(0, order)


def _wrap(block_type: int, body: bytes, order: ByteOrder) -> bytes:
    """Wrap a body in the standard pcap-ng block framing."""
    body = _pad4(body)
    total_length = 4 + 4 + len(body) + 4
    return _u32(block_type, order) + _u32(total_length, order) + body + _u32(total_length, order)


def _build_shb(
    order: ByteOrder = "little",
    *,
    major: int = 1,
    minor: int = 0,
    section_length: int = -1,
    options: bytes = b"",
) -> bytes:
    """Build a Section Header Block.

    The SHB has its own framing rules (block type is the same in both byte
    orders, length is BOM-dependent), so we don't go through ``_wrap``.
    """
    bom = b"\x4d\x3c\x2b\x1a" if order == "little" else b"\x1a\x2b\x3c\x4d"
    body = bom + _u16(major, order) + _u16(minor, order) + _i64(section_length, order)
    body = body + _pad4(options)
    total_length = 4 + 4 + len(body) + 4
    return b"\x0a\x0d\x0d\x0a" + _u32(total_length, order) + body + _u32(total_length, order)


def _build_idb(
    order: ByteOrder = "little",
    *,
    link_type: int = 189,  # LINKTYPE_USB_LINUX
    snap_len: int = 65535,
    options: bytes = b"",
) -> bytes:
    body = (
        _u16(link_type, order)
        + _u16(0, order)  # reserved
        + _u32(snap_len, order)
        + options
    )
    return _wrap(0x00000001, body, order)


def _build_epb(
    order: ByteOrder = "little",
    *,
    interface_id: int = 0,
    timestamp_high: int = 0,
    timestamp_low: int = 0,
    packet_data: bytes = b"\xde\xad\xbe\xef",
    original_len: int | None = None,
    options: bytes = b"",
) -> bytes:
    if original_len is None:
        original_len = len(packet_data)
    body = (
        _u32(interface_id, order)
        + _u32(timestamp_high, order)
        + _u32(timestamp_low, order)
        + _u32(len(packet_data), order)
        + _u32(original_len, order)
        + _pad4(packet_data)
        + options
    )
    return _wrap(0x00000006, body, order)


# --- Tests: basic happy paths ---------------------------------------------


@pytest.mark.parametrize("order", ["little", "big"])
def test_shb_only(order: ByteOrder) -> None:
    data = _build_shb(order)
    reader = PcapNgReader(io.BytesIO(data))
    blocks = list(reader)
    assert len(blocks) == 1
    block = blocks[0]
    assert isinstance(block, SectionHeaderBlock)
    assert block.byte_order == order
    assert block.major_version == 1
    assert block.minor_version == 0
    assert block.section_length == -1
    assert block.options == ()
    assert reader.byte_order == order


@pytest.mark.parametrize("order", ["little", "big"])
def test_shb_idb_epb_minimal(order: ByteOrder) -> None:
    payload = b"\x12\x34\x56\x78\x9a"
    data = _build_shb(order) + _build_idb(order) + _build_epb(order, packet_data=payload)
    blocks = list(PcapNgReader(io.BytesIO(data)))

    assert len(blocks) == 3
    shb, idb, epb = blocks
    assert isinstance(shb, SectionHeaderBlock)
    assert isinstance(idb, InterfaceDescriptionBlock)
    assert isinstance(epb, EnhancedPacketBlock)

    assert idb.link_type == 189
    assert idb.snap_len == 65535
    assert epb.interface_id == 0
    assert epb.captured_len == len(payload)
    assert epb.original_len == len(payload)
    assert epb.packet_data == payload


def test_options_parsing() -> None:
    # Build an SHB with two options: shb_hardware (2) and shb_os (3).
    options = _option(2, b"x86_64", "little") + _option(3, b"Linux 6.8", "little") + _opt_endofopt("little")
    data = _build_shb("little", options=options)
    blocks = list(PcapNgReader(io.BytesIO(data)))
    assert len(blocks) == 1
    shb = blocks[0]
    assert isinstance(shb, SectionHeaderBlock)
    assert len(shb.options) == 2
    assert shb.options[0].code == 2
    assert shb.options[0].value == b"x86_64"
    assert shb.options[1].code == 3
    assert shb.options[1].value == b"Linux 6.8"


def test_options_no_endofopt() -> None:
    # Options list that ends at the buffer boundary with no opt_endofopt record.
    # Exercises the implicit-termination path (reader.py line 140).
    options = _option(2, b"x86_64", "little") + _option(3, b"Linux 6.8", "little")
    data = _build_shb("little", options=options)
    blocks = list(PcapNgReader(io.BytesIO(data)))
    shb = blocks[0]
    assert isinstance(shb, SectionHeaderBlock)
    assert len(shb.options) == 2
    assert shb.options[0].value == b"x86_64"
    assert shb.options[1].value == b"Linux 6.8"


def test_reader_offset_advances() -> None:
    # Verify the offset property is updated after reading blocks.
    # Exercises the offset property getter (reader.py line 177).
    data = _build_shb("little") + _build_idb("little")
    reader = PcapNgReader(io.BytesIO(data))
    assert reader.offset == 0
    next(reader)
    assert reader.offset == len(_build_shb("little"))
    next(reader)
    assert reader.offset == len(data)


def test_unknown_block_preserved() -> None:
    # Use block type 0xDEADBEEF (not one we model).
    body = b"\xab\xcd\xef\x00"
    data = _build_shb("little") + _wrap(0xDEADBEEF, body, "little")
    blocks = list(PcapNgReader(io.BytesIO(data)))
    assert len(blocks) == 2
    unknown = blocks[1]
    assert isinstance(unknown, UnknownBlock)
    assert unknown.block_type == 0xDEADBEEF
    assert unknown.body == body


def test_isb_block() -> None:
    body = (
        _u32(0, "little")
        + _u32(0x12345678, "little")
        + _u32(0x9ABCDEF0, "little")
        + _option(2, b"\x05\x00\x00\x00\x00\x00\x00\x00", "little")
        + _opt_endofopt("little")
    )
    data = _build_shb("little") + _wrap(0x00000005, body, "little")
    blocks = list(PcapNgReader(io.BytesIO(data)))
    assert len(blocks) == 2
    isb = blocks[1]
    assert isinstance(isb, InterfaceStatisticsBlock)
    assert isb.interface_id == 0
    assert isb.timestamp_high == 0x12345678
    assert isb.timestamp_low == 0x9ABCDEF0
    assert len(isb.options) == 1


def test_spb_block() -> None:
    payload = b"hello!"
    body = _u32(len(payload), "little") + _pad4(payload)
    data = _build_shb("little") + _wrap(0x00000003, body, "little")
    blocks = list(PcapNgReader(io.BytesIO(data)))
    assert len(blocks) == 2
    spb = blocks[1]
    assert isinstance(spb, SimplePacketBlock)
    assert spb.original_len == len(payload)
    assert spb.packet_data == payload


def test_multiple_sections_switch_byte_order() -> None:
    # Section 1: little-endian, contains an IDB.
    # Section 2: big-endian, contains an IDB with a different link_type.
    data = (
        _build_shb("little")
        + _build_idb("little", link_type=189)
        + _build_shb("big")
        + _build_idb("big", link_type=220)
    )
    blocks = list(PcapNgReader(io.BytesIO(data)))
    assert len(blocks) == 4
    assert isinstance(blocks[0], SectionHeaderBlock)
    assert blocks[0].byte_order == "little"
    assert isinstance(blocks[1], InterfaceDescriptionBlock)
    assert blocks[1].link_type == 189
    assert isinstance(blocks[2], SectionHeaderBlock)
    assert blocks[2].byte_order == "big"
    assert isinstance(blocks[3], InterfaceDescriptionBlock)
    assert blocks[3].link_type == 220


# --- Tests: error paths ----------------------------------------------------


def test_empty_stream_yields_nothing() -> None:
    blocks = list(PcapNgReader(io.BytesIO(b"")))
    assert blocks == []


def test_first_block_must_be_shb() -> None:
    # A bare IDB at offset 0, no SHB — must raise.
    data = _build_idb("little")
    with pytest.raises(InvalidBlockError, match="not a Section Header Block"):
        list(PcapNgReader(io.BytesIO(data)))


def test_invalid_byte_order_magic() -> None:
    # Build something that looks like an SHB but has a corrupt BOM.
    bad = (
        b"\x0a\x0d\x0d\x0a"  # SHB type
        + b"\x1c\x00\x00\x00"  # total length = 28, little-endian-ish
        + b"\xff\xff\xff\xff"  # bogus BOM
        + b"\x01\x00\x00\x00"  # major/minor
        + b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section_length = -1
        + b"\x1c\x00\x00\x00"  # trailing length
    )
    with pytest.raises(InvalidBlockError, match="invalid byte-order magic"):
        list(PcapNgReader(io.BytesIO(bad)))


def test_unsupported_major_version() -> None:
    data = _build_shb("little", major=2)
    with pytest.raises(UnsupportedVersionError):
        list(PcapNgReader(io.BytesIO(data)))


def test_truncated_block_header() -> None:
    data = _build_shb("little") + b"\x01\x00"  # 2 bytes of a new block
    with pytest.raises(TruncatedFileError):
        list(PcapNgReader(io.BytesIO(data)))


def test_truncated_block_body() -> None:
    # Build a valid SHB, then a block whose declared length is more than
    # the bytes that follow.
    valid = _build_shb("little")
    # Block type 0x00000001, declared total length 100, but only 8 bytes follow.
    truncated = b"\x01\x00\x00\x00" + b"\x64\x00\x00\x00" + b"\x00" * 8
    with pytest.raises(TruncatedFileError):
        list(PcapNgReader(io.BytesIO(valid + truncated)))


def test_mismatched_trailing_length() -> None:
    # Build a manually corrupted IDB: leading length 20, trailing length 24.
    body = _u16(189, "little") + _u16(0, "little") + _u32(65535, "little")
    body = _pad4(body)
    bad = (
        _u32(0x00000001, "little")
        + _u32(20, "little")  # leading
        + body
        + _u32(24, "little")  # trailing — wrong on purpose
    )
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="trailing length"):
        list(PcapNgReader(io.BytesIO(data)))


def test_misaligned_block_length() -> None:
    # Block total length not a multiple of 4.
    bad = _u32(0x00000001, "little") + _u32(21, "little") + b"\x00" * 13
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="multiple of 4"):
        list(PcapNgReader(io.BytesIO(data)))


def test_option_length_overruns_block() -> None:
    # IDB with an option whose declared length exceeds the remaining bytes.
    options = _u16(2, "little") + _u16(99, "little") + b"\x00" * 4
    body = _u16(189, "little") + _u16(0, "little") + _u32(65535, "little") + options
    data = _build_shb("little") + _wrap(0x00000001, body, "little")
    with pytest.raises(InvalidBlockError, match="option"):
        list(PcapNgReader(io.BytesIO(data)))


def test_epb_captured_len_overruns_body() -> None:
    # EPB declares captured_len = 100 but provides 4 bytes of payload.
    body = (
        _u32(0, "little")  # interface_id
        + _u32(0, "little")  # ts_high
        + _u32(0, "little")  # ts_low
        + _u32(100, "little")  # captured_len (lie)
        + _u32(100, "little")  # original_len
        + b"\xaa\xbb\xcc\xdd"
    )
    data = _build_shb("little") + _wrap(0x00000006, body, "little")
    with pytest.raises(InvalidBlockError, match="captured_len"):
        list(PcapNgReader(io.BytesIO(data)))


def test_shb_total_length_below_minimum() -> None:
    """SHB whose declared total length is below the 28-byte minimum must raise."""
    data = (
        b"\x0a\x0d\x0d\x0a"
        + _u32(16, "little")  # total length = 16 (below 28)
        + b"\x4d\x3c\x2b\x1a"  # BOM
    )
    with pytest.raises(InvalidBlockError, match="below minimum"):
        list(PcapNgReader(io.BytesIO(data)))


def test_shb_total_length_not_aligned() -> None:
    """SHB whose declared total length is not a multiple of 4 must raise."""
    data = (
        b"\x0a\x0d\x0d\x0a"
        + _u32(29, "little")  # not divisible by 4
        + b"\x4d\x3c\x2b\x1a"
    )
    with pytest.raises(InvalidBlockError, match="multiple of 4"):
        list(PcapNgReader(io.BytesIO(data)))


def test_shb_trailing_length_mismatch() -> None:
    """SHB whose trailing length disagrees with its leading length must raise."""
    data = (
        b"\x0a\x0d\x0d\x0a"
        + _u32(28, "little")  # leading length
        + b"\x4d\x3c\x2b\x1a"  # BOM
        + _u16(1, "little")  # major
        + _u16(0, "little")  # minor
        + _i64(-1, "little")  # section_length
        + _u32(99, "little")  # trailing length (wrong)
    )
    with pytest.raises(InvalidBlockError, match="SHB trailing length"):
        list(PcapNgReader(io.BytesIO(data)))


def test_generic_block_total_length_below_minimum() -> None:
    """A non-SHB block whose total length is below 12 must raise."""
    bad = _u32(0x00000001, "little") + _u32(8, "little")  # length = 8
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="below minimum"):
        list(PcapNgReader(io.BytesIO(data)))


def test_idb_body_too_small() -> None:
    """IDB whose body is shorter than the fixed-header size must raise."""
    # total_length = 16 → body = 4 bytes, less than _MIN_IDB_BODY (8)
    bad = _u32(0x00000001, "little") + _u32(16, "little") + b"\x00" * 4 + _u32(16, "little")
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="IDB body too small"):
        list(PcapNgReader(io.BytesIO(data)))


def test_epb_body_too_small() -> None:
    """EPB whose body is shorter than the fixed-header size must raise."""
    # total_length = 24 → body = 12 bytes, less than _MIN_EPB_BODY (20)
    bad = _u32(0x00000006, "little") + _u32(24, "little") + b"\x00" * 12 + _u32(24, "little")
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="EPB body too small"):
        list(PcapNgReader(io.BytesIO(data)))


def test_spb_body_too_small() -> None:
    """SPB with an empty body must raise."""
    # total_length = 12 → body = 0 bytes, less than _MIN_SPB_BODY (4)
    bad = _u32(0x00000003, "little") + _u32(12, "little") + _u32(12, "little")
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="SPB body too small"):
        list(PcapNgReader(io.BytesIO(data)))


def test_isb_body_too_small() -> None:
    """ISB whose body is shorter than the fixed-header size must raise."""
    # total_length = 20 → body = 8 bytes, less than _MIN_ISB_BODY (12)
    bad = _u32(0x00000005, "little") + _u32(20, "little") + b"\x00" * 8 + _u32(20, "little")
    data = _build_shb("little") + bad
    with pytest.raises(InvalidBlockError, match="ISB body too small"):
        list(PcapNgReader(io.BytesIO(data)))
