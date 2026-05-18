"""pcap-ng block reader for bsu-tool.

The reader is intentionally layered: this module decodes pcap-ng *block*
structure only. URB-level decoding of packet payloads belongs in a
separate module so the two layers can be tested independently.

Typical use::

    from bsu_tool.pcapng_reader import PcapNgReader, EnhancedPacketBlock

    with open("capture.pcapng", "rb") as fp:
        for block in PcapNgReader(fp):
            if isinstance(block, EnhancedPacketBlock):
                ...  # do something with block.packet_data

Block types
-----------
Every block we expose is a frozen dataclass — once parsed, blocks are
immutable. Options are exposed as a tuple of raw :class:`Option` records;
higher-level code is responsible for interpreting option codes by context
(option codes are not globally unique — code 2 means something different
inside an SHB than inside an EPB).

We model the well-known block types we expect to see in usbmon captures
(Section Header, Interface Description, Enhanced Packet, Simple Packet,
Interface Statistics) and fall back to :class:`UnknownBlock` for anything
else, so callers never lose data.

Error types
-----------
All parser-level exceptions inherit from :class:`PcapNgError`, so callers
that just want to report parse failures can catch a single base class.

References
----------
The pcap-ng format is specified in
https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html and the
older Wireshark wiki at https://wiki.wireshark.org/Development/PcapNg.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO, Final, Literal

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------

#: Endianness of a section, established by the byte-order magic in its SHB.
ByteOrder = Literal["little", "big"]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PcapNgError(Exception):
    """Base class for all pcap-ng parser errors."""


class TruncatedFileError(PcapNgError):
    """Raised when the input stream ends in the middle of a block.

    This is distinct from a clean end-of-stream between blocks, which the
    reader signals via normal iterator termination (``StopIteration``).
    """


class InvalidBlockError(PcapNgError):
    """Raised when a block is structurally invalid.

    Examples include: a block-total-length that is not a multiple of 4,
    a leading and trailing total-length that disagree, an option whose
    declared length runs off the end of the block, or a Section Header
    Block with an unrecognized byte-order magic.
    """


class UnsupportedVersionError(PcapNgError):
    """Raised when a Section Header Block declares a major version we do not support.

    We accept pcap-ng major version 1; any other value raises this.
    """


# ---------------------------------------------------------------------------
# Block dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Option:
    """A single TLV option from a block's options list.

    Options are stored as raw bytes; the parser deliberately does not try
    to interpret well-known option codes (e.g. ``opt_comment``) because
    interpretation depends on which block type the option appears in.
    """

    code: int
    value: bytes


@dataclass(frozen=True, slots=True)
class SectionHeaderBlock:
    """Section Header Block (block type ``0x0A0D0D0A``).

    Marks the start of a section. ``section_length`` is signed: a value of
    -1 means the writer did not record the length (common for live captures).
    """

    byte_order: ByteOrder
    major_version: int
    minor_version: int
    section_length: int
    options: tuple[Option, ...]


@dataclass(frozen=True, slots=True)
class InterfaceDescriptionBlock:
    """Interface Description Block (block type ``0x00000001``).

    Describes one capture interface. ``link_type`` is the LINKTYPE_*
    value defined by tcpdump.org; usbmon captures use LINKTYPE_USB_LINUX
    (189) or LINKTYPE_USB_LINUX_MMAPPED (220).
    """

    link_type: int
    snap_len: int
    options: tuple[Option, ...]


@dataclass(frozen=True, slots=True)
class EnhancedPacketBlock:
    """Enhanced Packet Block (block type ``0x00000006``).

    The standard form for captured packets in modern pcap-ng files. The
    timestamp is split into a high and low 32-bit word; the units are
    determined by the ``if_tsresol`` option of the referenced interface
    (default: microseconds).
    """

    interface_id: int
    timestamp_high: int
    timestamp_low: int
    captured_len: int
    original_len: int
    packet_data: bytes
    options: tuple[Option, ...]


@dataclass(frozen=True, slots=True)
class SimplePacketBlock:
    """Simple Packet Block (block type ``0x00000003``).

    A stripped-down packet block with no timestamp and no interface id —
    it implicitly belongs to interface 0. Rare in usbmon captures but
    cheap to support.
    """

    original_len: int
    packet_data: bytes


@dataclass(frozen=True, slots=True)
class InterfaceStatisticsBlock:
    """Interface Statistics Block (block type ``0x00000005``).

    Per-interface counters (packets received, dropped, etc.) emitted at
    capture stop time. The actual statistics live in the options.
    """

    interface_id: int
    timestamp_high: int
    timestamp_low: int
    options: tuple[Option, ...]


@dataclass(frozen=True, slots=True)
class UnknownBlock:
    """A block whose type we do not specifically model.

    The body is exposed verbatim (with its trailing total-length stripped)
    so that callers can implement support for additional block types
    without modifying the parser.
    """

    block_type: int
    body: bytes


#: Tagged union of every block type the parser can yield.
Block = (
    SectionHeaderBlock
    | InterfaceDescriptionBlock
    | EnhancedPacketBlock
    | SimplePacketBlock
    | InterfaceStatisticsBlock
    | UnknownBlock
)


# ---------------------------------------------------------------------------
# Block-type identifiers
# ---------------------------------------------------------------------------

#: Section Header Block. The byte sequence ``0a 0d 0d 0a`` is a palindrome,
#: so we can recognize the SHB before we know the section's byte order.
_BLOCK_TYPE_SHB: Final[int] = 0x0A0D0D0A
_SHB_TYPE_BYTES: Final[bytes] = b"\x0a\x0d\x0d\x0a"

_BLOCK_TYPE_IDB: Final[int] = 0x00000001
_BLOCK_TYPE_SPB: Final[int] = 0x00000003
_BLOCK_TYPE_ISB: Final[int] = 0x00000005
_BLOCK_TYPE_EPB: Final[int] = 0x00000006

# ---------------------------------------------------------------------------
# Byte-order magic
# ---------------------------------------------------------------------------

#: Byte-order magic as it appears on the wire when the section is little-endian.
_BOM_LITTLE: Final[bytes] = b"\x4d\x3c\x2b\x1a"
#: Byte-order magic as it appears on the wire when the section is big-endian.
_BOM_BIG: Final[bytes] = b"\x1a\x2b\x3c\x4d"

# ---------------------------------------------------------------------------
# Version and option constants
# ---------------------------------------------------------------------------

_SUPPORTED_MAJOR: Final[int] = 1

#: Option code that terminates an options list (``opt_endofopt``).
_OPT_ENDOFOPT: Final[int] = 0

# ---------------------------------------------------------------------------
# Minimum block sizes
# ---------------------------------------------------------------------------
# Every block has the 12-byte framing: type(4) + length(4) + length(4).
# The constants below are minimum *body* sizes — the bytes between the
# leading and trailing length fields.

_MIN_BLOCK_SIZE: Final[int] = 12

# SHB body = BOM(4) + major(2) + minor(2) + section_length(8) = 16 bytes.
_MIN_SHB_BODY: Final[int] = 16
_MIN_SHB_SIZE: Final[int] = _MIN_BLOCK_SIZE + _MIN_SHB_BODY

# IDB body = link_type(2) + reserved(2) + snap_len(4) = 8 bytes.
_MIN_IDB_BODY: Final[int] = 8

# EPB body = interface_id(4) + ts_high(4) + ts_low(4)
#          + captured_len(4) + original_len(4) = 20 bytes.
_MIN_EPB_BODY: Final[int] = 20

# SPB body = original_len(4) = 4 bytes.
_MIN_SPB_BODY: Final[int] = 4

# ISB body = interface_id(4) + ts_high(4) + ts_low(4) = 12 bytes.
_MIN_ISB_BODY: Final[int] = 12


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pad4(n: int) -> int:
    """Round ``n`` up to the next multiple of 4."""
    return (n + 3) & ~3


def _parse_options(data: bytes, byte_order: ByteOrder) -> tuple[Option, ...]:
    """Parse a sequence of TLV options.

    The list is terminated either by an ``opt_endofopt`` record (code 0,
    length 0) or by the end of ``data``. Each option's value is padded to
    a 4-byte boundary on the wire; the padding is consumed but not
    included in the returned :class:`Option`.
    """
    if not data:
        return ()

    options: list[Option] = []
    pos = 0
    end = len(data)

    while pos + 4 <= end:
        code = int.from_bytes(data[pos : pos + 2], byte_order)
        length = int.from_bytes(data[pos + 2 : pos + 4], byte_order)
        pos += 4

        if code == _OPT_ENDOFOPT and length == 0:
            return tuple(options)

        if pos + length > end:
            raise InvalidBlockError(f"option code {code} declares length {length} but only {end - pos} bytes remain")

        value = bytes(data[pos : pos + length])
        options.append(Option(code=code, value=value))
        pos += _pad4(length)

    return tuple(options)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


class PcapNgReader:
    """Iterates the blocks of a pcap-ng stream.

    Parameters
    ----------
    stream:
        A binary, readable file-like object positioned at the start of a
        pcap-ng file. The reader does not seek; a non-seekable stream
        (e.g. a pipe) works fine.

    The reader is its own iterator::

        with open("capture.pcapng", "rb") as fp:
            for block in PcapNgReader(fp):
                ...
    """

    __slots__ = ("_byte_order", "_offset", "_stream")

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._byte_order: ByteOrder | None = None
        self._offset = 0

    @property
    def byte_order(self) -> ByteOrder | None:
        """The byte order of the current section, or ``None`` before the first SHB."""
        return self._byte_order

    @property
    def offset(self) -> int:
        """The current byte offset within the stream."""
        return self._offset

    def __iter__(self) -> Iterator[Block]:
        return self

    def __next__(self) -> Block:
        type_bytes = self._stream.read(4)
        if len(type_bytes) == 0:
            raise StopIteration
        if len(type_bytes) < 4:
            raise TruncatedFileError(f"at offset {self._offset}: truncated block type ({len(type_bytes)} of 4 bytes)")
        self._offset += 4

        if type_bytes == _SHB_TYPE_BYTES:
            return self._read_shb()

        if self._byte_order is None:
            raise InvalidBlockError(f"at offset {self._offset - 4}: first block is not a Section Header Block")

        block_type = int.from_bytes(type_bytes, self._byte_order)
        return self._read_generic_block(block_type)

    def _read_exact(self, n: int) -> bytes:
        """Read exactly ``n`` bytes or raise :class:`TruncatedFileError`."""
        data = self._stream.read(n)
        if len(data) != n:
            raise TruncatedFileError(f"at offset {self._offset}: expected {n} bytes, got {len(data)}")
        self._offset += n
        return data

    def _read_shb(self) -> SectionHeaderBlock:
        """Read the rest of a Section Header Block.

        Called after the 4-byte block type has already been consumed.
        Establishes the section's byte order from the BOM; this byte
        order then applies to every block until the next SHB.
        """
        block_start = self._offset - 4

        # Read the next 8 bytes (length + BOM) to resolve byte order first.
        head = self._read_exact(8)
        bom = head[4:8]

        if bom == _BOM_LITTLE:
            byte_order: ByteOrder = "little"
        elif bom == _BOM_BIG:
            byte_order = "big"
        else:
            raise InvalidBlockError(f"at offset {block_start}: invalid byte-order magic {bom.hex()}")

        total_length = int.from_bytes(head[0:4], byte_order)
        if total_length < _MIN_SHB_SIZE:
            raise InvalidBlockError(
                f"at offset {block_start}: SHB total length {total_length} below minimum {_MIN_SHB_SIZE}"
            )
        if total_length % 4 != 0:
            raise InvalidBlockError(f"at offset {block_start}: SHB total length {total_length} is not a multiple of 4")

        # Consumed: 4 (type) + 4 (length) + 4 (BOM) = 12 bytes so far.
        rest = self._read_exact(total_length - 12)

        major = int.from_bytes(rest[0:2], byte_order)
        minor = int.from_bytes(rest[2:4], byte_order)
        section_length = int.from_bytes(rest[4:12], byte_order, signed=True)

        options_data = rest[12:-4]
        trailing_length = int.from_bytes(rest[-4:], byte_order)
        if trailing_length != total_length:
            raise InvalidBlockError(
                f"at offset {block_start}: SHB trailing length {trailing_length} != leading length {total_length}"
            )

        if major != _SUPPORTED_MAJOR:
            raise UnsupportedVersionError(f"at offset {block_start}: unsupported pcap-ng version {major}.{minor}")

        options = _parse_options(options_data, byte_order)
        self._byte_order = byte_order

        return SectionHeaderBlock(
            byte_order=byte_order,
            major_version=major,
            minor_version=minor,
            section_length=section_length,
            options=options,
        )

    def _read_generic_block(self, block_type: int) -> Block:
        """Read a non-SHB block.

        Called after the 4-byte block type has been consumed and the
        section's byte order is known.
        """
        assert self._byte_order is not None  # checked by caller
        byte_order = self._byte_order
        block_start = self._offset - 4

        total_length_bytes = self._read_exact(4)
        total_length = int.from_bytes(total_length_bytes, byte_order)

        if total_length < _MIN_BLOCK_SIZE:
            raise InvalidBlockError(
                f"at offset {block_start}: block total length {total_length} below minimum {_MIN_BLOCK_SIZE}"
            )
        if total_length % 4 != 0:
            raise InvalidBlockError(
                f"at offset {block_start}: block total length {total_length} is not a multiple of 4"
            )

        body_with_trailer = self._read_exact(total_length - 8)
        body = body_with_trailer[:-4]
        trailing_length = int.from_bytes(body_with_trailer[-4:], byte_order)
        if trailing_length != total_length:
            raise InvalidBlockError(
                f"at offset {block_start}: block trailing length {trailing_length} != leading length {total_length}"
            )

        return self._dispatch(block_type, body, byte_order, block_start)

    def _dispatch(
        self,
        block_type: int,
        body: bytes,
        byte_order: ByteOrder,
        block_start: int,
    ) -> Block:
        """Dispatch a validated block body to its type-specific parser."""
        if block_type == _BLOCK_TYPE_IDB:
            return self._parse_idb(body, byte_order, block_start)
        if block_type == _BLOCK_TYPE_EPB:
            return self._parse_epb(body, byte_order, block_start)
        if block_type == _BLOCK_TYPE_SPB:
            return self._parse_spb(body, byte_order, block_start)
        if block_type == _BLOCK_TYPE_ISB:
            return self._parse_isb(body, byte_order, block_start)
        return UnknownBlock(block_type=block_type, body=bytes(body))

    @staticmethod
    def _parse_idb(body: bytes, byte_order: ByteOrder, block_start: int) -> InterfaceDescriptionBlock:
        if len(body) < _MIN_IDB_BODY:
            raise InvalidBlockError(f"at offset {block_start}: IDB body too small ({len(body)} bytes)")
        link_type = int.from_bytes(body[0:2], byte_order)
        snap_len = int.from_bytes(body[4:8], byte_order)
        options = _parse_options(body[8:], byte_order)
        return InterfaceDescriptionBlock(link_type=link_type, snap_len=snap_len, options=options)

    @staticmethod
    def _parse_epb(body: bytes, byte_order: ByteOrder, block_start: int) -> EnhancedPacketBlock:
        if len(body) < _MIN_EPB_BODY:
            raise InvalidBlockError(f"at offset {block_start}: EPB body too small ({len(body)} bytes)")
        interface_id = int.from_bytes(body[0:4], byte_order)
        timestamp_high = int.from_bytes(body[4:8], byte_order)
        timestamp_low = int.from_bytes(body[8:12], byte_order)
        captured_len = int.from_bytes(body[12:16], byte_order)
        original_len = int.from_bytes(body[16:20], byte_order)

        data_start = 20
        data_end = data_start + captured_len
        if data_end > len(body):
            raise InvalidBlockError(
                f"at offset {block_start}: EPB captured_len {captured_len} "
                f"exceeds remaining body size {len(body) - data_start}"
            )

        packet_data = bytes(body[data_start:data_end])
        options_start = data_start + _pad4(captured_len)
        if options_start > len(body):
            raise InvalidBlockError(f"at offset {block_start}: EPB padding runs past block end")
        options = _parse_options(body[options_start:], byte_order)

        return EnhancedPacketBlock(
            interface_id=interface_id,
            timestamp_high=timestamp_high,
            timestamp_low=timestamp_low,
            captured_len=captured_len,
            original_len=original_len,
            packet_data=packet_data,
            options=options,
        )

    @staticmethod
    def _parse_spb(body: bytes, byte_order: ByteOrder, block_start: int) -> SimplePacketBlock:
        if len(body) < _MIN_SPB_BODY:
            raise InvalidBlockError(f"at offset {block_start}: SPB body too small ({len(body)} bytes)")
        original_len = int.from_bytes(body[0:4], byte_order)
        captured = min(original_len, len(body) - 4)
        packet_data = bytes(body[4 : 4 + captured])
        return SimplePacketBlock(original_len=original_len, packet_data=packet_data)

    @staticmethod
    def _parse_isb(body: bytes, byte_order: ByteOrder, block_start: int) -> InterfaceStatisticsBlock:
        if len(body) < _MIN_ISB_BODY:
            raise InvalidBlockError(f"at offset {block_start}: ISB body too small ({len(body)} bytes)")
        interface_id = int.from_bytes(body[0:4], byte_order)
        timestamp_high = int.from_bytes(body[4:8], byte_order)
        timestamp_low = int.from_bytes(body[8:12], byte_order)
        options = _parse_options(body[12:], byte_order)
        return InterfaceStatisticsBlock(
            interface_id=interface_id,
            timestamp_high=timestamp_high,
            timestamp_low=timestamp_low,
            options=options,
        )


__all__ = [
    "Block",
    "ByteOrder",
    "EnhancedPacketBlock",
    "InterfaceDescriptionBlock",
    "InterfaceStatisticsBlock",
    "InvalidBlockError",
    "Option",
    "PcapNgError",
    "PcapNgReader",
    "SectionHeaderBlock",
    "SimplePacketBlock",
    "TruncatedFileError",
    "UnknownBlock",
    "UnsupportedVersionError",
]
