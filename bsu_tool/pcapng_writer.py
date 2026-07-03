"""pcap-ng block writer for bsu-tool.

Counterpart to :mod:`bsu_tool.pcapng_reader`. The split mirrors the
read path: this module handles pcap-ng *block* structure; URB-level
encoding of packet payloads is the caller's responsibility (the
sniffer passes through raw bytes received from the kernel's usbmon
interface).

Typical use::

    from bsu_tool.pcapng_writer import PcapNgWriter
    from bsu_tool.urb_decoder import LINKTYPE_USB_LINUX_MMAPPED

    with open("capture.pcapng", "xb") as fp:
        writer = PcapNgWriter(fp)
        writer.write_section_header()
        iface = writer.write_interface_description(
            link_type=LINKTYPE_USB_LINUX_MMAPPED,
        )
        for hdr_plus_data, timestamp_us in events:
            writer.write_enhanced_packet(iface, timestamp_us, hdr_plus_data)

Design choices
--------------
* The stream is owned by the caller. The writer never opens, closes,
  or flushes the stream; the caller's ``with`` block handles that.
* Interface IDs are auto-assigned in registration order, starting at 0.
  Callers reference interfaces by the returned ID when writing EPBs.
* Timestamps are passed as a single integer count of ``tsresol`` ticks
  (microseconds by default). The 64-bit-as-two-32-bit-words split that
  pcap-ng requires is internal to this module.
* All blocks are written to the stream immediately; nothing is buffered.
  A SIGINT mid-capture leaves a structurally valid file with every block
  that completed before the signal.

Byte order is little-endian on the wire. The spec permits big-endian
sections, but every modern tool (tshark, Wireshark, scapy) writes
little-endian, so we do too.
"""

from __future__ import annotations

from typing import BinaryIO, Final

# ---------------------------------------------------------------------------
# Block-type identifiers (must match pcapng_reader.py)
# ---------------------------------------------------------------------------

_BLOCK_TYPE_SHB: Final[int] = 0x0A0D0D0A
_BLOCK_TYPE_IDB: Final[int] = 0x00000001
_BLOCK_TYPE_EPB: Final[int] = 0x00000006

# Byte-order magic for a little-endian section.
_BOM_LITTLE: Final[int] = 0x1A2B3C4D

# pcap-ng version we write. The format has been at 1.0 since 2004 and the
# draft RFC keeps it pinned at 1.x.
_VERSION_MAJOR: Final[int] = 1
_VERSION_MINOR: Final[int] = 0

# Section length = -1 means "unknown" (live capture, no rewind). pcap-ng
# permits this and every streaming writer uses it.
_SECTION_LENGTH_UNKNOWN: Final[int] = -1

# Default snap length: 65535 matches tshark's default and is large enough
# for any single USB transfer we expect to see.
_DEFAULT_SNAP_LEN: Final[int] = 65535

# Option code for if_tsresol on an IDB. Value is a single byte: low 7 bits
# are the exponent, high bit selects power-of-10 (0) vs power-of-2 (1).
# 0x06 = 10^-6 seconds = microseconds, matching usbmon's native resolution.
_OPT_IF_TSRESOL: Final[int] = 9
_OPT_ENDOFOPT: Final[int] = 0

#: Endianness used for all multi-byte fields in written blocks.
_BYTE_ORDER: Final[str] = "little"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pad4(n: int) -> int:
    """Round ``n`` up to the next multiple of 4."""
    return (n + 3) & ~3


def _padding(n: int) -> bytes:
    """Return the zero bytes needed to pad ``n`` up to a 4-byte boundary."""
    return b"\x00" * (_pad4(n) - n)


def _u16(value: int) -> bytes:
    return value.to_bytes(2, _BYTE_ORDER, signed=False)


def _u32(value: int) -> bytes:
    return value.to_bytes(4, _BYTE_ORDER, signed=False)


def _i64(value: int) -> bytes:
    return value.to_bytes(8, _BYTE_ORDER, signed=True)


def _option(code: int, value: bytes) -> bytes:
    """Encode one TLV option, including trailing pad-to-4 alignment."""
    return _u16(code) + _u16(len(value)) + value + _padding(len(value))


def _end_of_options() -> bytes:
    """Encode the opt_endofopt terminator (code 0, length 0)."""
    return _u16(_OPT_ENDOFOPT) + _u16(0)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class PcapNgWriter:
    """Writes pcap-ng blocks to a binary stream.

    The writer is stateful in exactly one way: it tracks the number of
    interfaces registered so far, so that :meth:`write_interface_description`
    can return the auto-assigned interface ID. EPBs reference interfaces
    by this ID.

    Parameters
    ----------
    stream:
        A binary, writable file-like object. The writer does not seek
        and does not close the stream.
    """

    __slots__ = ("_interface_count", "_stream")

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._interface_count = 0

    @property
    def interface_count(self) -> int:
        """Number of IDBs written so far in the current section."""
        return self._interface_count

    # -- SHB ---------------------------------------------------------------

    def write_section_header(self) -> None:
        """Write a Section Header Block.

        Must be the first block in the file. A section length of -1 is
        written, indicating "unknown" — appropriate for a live capture
        where the writer cannot know the final size in advance.

        Calling this method again starts a new section; the interface
        counter resets to 0.
        """
        # Body layout: BOM(4) + major(2) + minor(2) + section_length(8)
        body = _u32(_BOM_LITTLE) + _u16(_VERSION_MAJOR) + _u16(_VERSION_MINOR) + _i64(_SECTION_LENGTH_UNKNOWN)
        self._write_block(_BLOCK_TYPE_SHB, body)
        self._interface_count = 0

    # -- IDB ---------------------------------------------------------------

    def write_interface_description(
        self,
        link_type: int,
        snap_len: int = _DEFAULT_SNAP_LEN,
        *,
        tsresol_exponent: int = 6,
    ) -> int:
        """Write an Interface Description Block.

        Parameters
        ----------
        link_type:
            LINKTYPE_* value identifying the link-layer format of packets
            on this interface. For usbmon captures, use
            :data:`bsu_tool.urb_decoder.LINKTYPE_USB_LINUX_MMAPPED`.
        snap_len:
            Maximum captured packet size in bytes. Defaults to 65535,
            matching tshark.
        tsresol_exponent:
            Timestamp resolution exponent. ``6`` means 10^-6 seconds
            (microseconds), which matches the resolution of the
            usbmon header's ``ts_sec``/``ts_usec`` fields.

        Returns
        -------
        int
            The interface ID assigned to this interface (0 for the first
            IDB in a section, 1 for the second, and so on). Callers pass
            this ID to :meth:`write_enhanced_packet`.
        """
        # IDB body: link_type(2) + reserved(2) + snap_len(4) + options
        body = (
            _u16(link_type)
            + _u16(0)  # reserved, must be zero
            + _u32(snap_len)
            + _option(_OPT_IF_TSRESOL, bytes([tsresol_exponent]))
            + _end_of_options()
        )
        self._write_block(_BLOCK_TYPE_IDB, body)
        assigned_id = self._interface_count
        self._interface_count += 1
        return assigned_id

    # -- EPB ---------------------------------------------------------------

    def write_enhanced_packet(
        self,
        interface_id: int,
        timestamp_us: int,
        packet_data: bytes,
        *,
        original_length: int | None = None,
    ) -> None:
        """Write an Enhanced Packet Block.

        Parameters
        ----------
        interface_id:
            ID returned by a prior :meth:`write_interface_description`
            call in the current section.
        timestamp_us:
            Microseconds since the Unix epoch. For usbmon events,
            compute as ``ts_sec * 1_000_000 + ts_usec``.
        packet_data:
            The raw packet bytes — for usbmon, the complete header plus
            captured data, exactly as obtained from the kernel.
        original_length:
            Length on the wire before any snap-len truncation. Defaults
            to ``len(packet_data)``; callers that truncate must pass the
            untruncated length explicitly.

        Raises
        ------
        ValueError
            If ``interface_id`` references an interface that has not been
            registered, or if ``timestamp_us`` does not fit in 64 bits.
        """
        if interface_id < 0 or interface_id >= self._interface_count:
            raise ValueError(f"interface_id {interface_id} not registered (have {self._interface_count} interface(s))")
        if timestamp_us < 0 or timestamp_us >= (1 << 64):
            raise ValueError(f"timestamp_us {timestamp_us} out of 64-bit range")

        captured_length = len(packet_data)
        if original_length is None:
            original_length = captured_length

        ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
        ts_low = timestamp_us & 0xFFFFFFFF

        # EPB body: interface_id(4) + ts_high(4) + ts_low(4) +
        #           captured_len(4) + original_len(4) +
        #           packet_data + pad-to-4 + options
        body = (
            _u32(interface_id)
            + _u32(ts_high)
            + _u32(ts_low)
            + _u32(captured_length)
            + _u32(original_length)
            + packet_data
            + _padding(captured_length)
            + _end_of_options()
        )
        self._write_block(_BLOCK_TYPE_EPB, body)

    # -- block framing -----------------------------------------------------

    def _write_block(self, block_type: int, body: bytes) -> None:
        """Wrap ``body`` in pcap-ng block framing and write it to the stream.

        Each block is::

            block_type(4) + total_length(4) + body + total_length(4)

        where ``total_length`` is the size of the entire block including
        the type, both length fields, and the body. The body has already
        been padded to a 4-byte boundary by the caller.
        """
        total_length = 4 + 4 + len(body) + 4
        framed = _u32(block_type) + _u32(total_length) + body + _u32(total_length)
        self._stream.write(framed)


__all__ = ["PcapNgWriter"]
