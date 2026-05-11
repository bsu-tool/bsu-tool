"""Data classes representing pcap-ng blocks.

Every block we expose is a frozen dataclass — once parsed, blocks are
immutable. Options are exposed as a tuple of raw :class:`Option` records;
higher-level code is responsible for interpreting option codes by context
(option codes are not globally unique — code 2 means something different
inside an SHB than inside an EPB).

We model the well-known block types we expect to see in usbmon captures
(Section Header, Interface Description, Enhanced Packet, Simple Packet,
Interface Statistics) and fall back to :class:`UnknownBlock` for anything
else, so callers never lose data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: Endianness of a section, established by the byte-order magic in its SHB.
ByteOrder = Literal["little", "big"]


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
