"""USB Request Block decoder for Linux usbmon captures.

This module turns the raw bytes of a captured USB packet into a fully
typed :class:`UrbRecord`, and groups streams of records into
:class:`UrbTransaction` objects by URB id (pairing each submission with
its completion).

Two operations are exposed:

* :func:`decode_urb` — single-packet decode. Takes the raw payload of a
  pcap-ng Enhanced or Simple Packet Block whose source interface
  declared a USB link type, plus the link-type integer, and returns a
  :class:`UrbRecord`.
* :func:`pair_urbs` — stream-pairing. Consumes an iterable of
  :class:`UrbRecord` events in capture order and yields
  :class:`UrbTransaction` objects.

Scope (Milestone 1):

* Control and Bulk transfers are decoded.
* Interrupt transfers are scheduled for Milestone 2 and intentionally
  raise :class:`UnsupportedTransferTypeError`.
* Isochronous transfers are out of scope for this project entirely and
  also raise :class:`UnsupportedTransferTypeError`.

64-byte usbmon header layout (LINKTYPE_USB_LINUX_MMAPPED = 220):

    Offset  Size  Field           Type   Notes
    ------  ----  --------------  -----  ------------------------------
         0     8  urb_id          u64    identical across S/C of one URB
         8     1  event_type      u8     'S'/'C'/'E' as raw ASCII byte
         9     1  xfer_type       u8     0=iso 1=intr 2=ctrl 3=bulk
        10     1  epnum           u8     dir in bit 7, ep# in bits 0-3
        11     1  devnum          u8     device address on the bus
        12     2  busnum          u16    bus number
        14     1  flag_setup      u8     0 if 8-byte setup field is valid
        15     1  flag_data       u8     data-presence marker; unused here
        16     8  ts_sec          s64    timestamp seconds
        24     4  ts_usec         s32    timestamp microseconds
        28     4  status          s32    kernel errno; 0 on success
        32     4  length          u32    reported length of data phase
        36     4  len_cap         u32    bytes actually captured
        40     8  setup           [8]u8  USB setup packet (control only)
        48     4  interval        s32    periodic interval (mmapped only)
        52     4  start_frame     s32    ISO start frame (mmapped only)
        56     4  xfer_flags      u32    URB transfer flags (mmapped only)
        60     4  ndesc           u32    ISO descriptor count (mmapped only)

The older LINKTYPE_USB_LINUX (189) layout is the first 48 bytes only.
All multi-byte fields are little-endian on Linux.

References
----------
* Linux kernel ``Documentation/usb/usbmon.rst``
* USB 2.0 specification, Chapter 8 (Protocol Layer) and Chapter 9
  (USB Device Framework) — see Section 9.3 for the setup-packet layout
* tcpdump.org LINKTYPE registry: https://www.tcpdump.org/linktypes.html
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Final, Literal

# --- Public type aliases ---------------------------------------------------

EventType = Literal["submission", "completion", "error"]
TransferType = Literal["control", "bulk"]
Direction = Literal["in", "out"]

# --- Link-type constants ---------------------------------------------------

#: Older Linux usbmon link type; 48-byte header.
LINKTYPE_USB_LINUX: Final = 189
#: Newer Linux usbmon link type; 64-byte header. Modern captures use this.
LINKTYPE_USB_LINUX_MMAPPED: Final = 220

#: On-wire size of the 48-byte basic header.
HEADER_SIZE_USB_LINUX: Final = 48
#: On-wire size of the 64-byte mmapped header.
HEADER_SIZE_USB_LINUX_MMAPPED: Final = 64

# --- Wire-format byte values ----------------------------------------------

# Transfer-type byte (offset 9 in the header).
_XFER_ISOCHRONOUS: Final = 0
_XFER_INTERRUPT: Final = 1
_XFER_CONTROL: Final = 2
_XFER_BULK: Final = 3

# Event-type byte (offset 8). Stored by the kernel as ASCII characters.
_EVENT_SUBMIT_BYTE: Final = 0x53  # 'S'
_EVENT_COMPLETE_BYTE: Final = 0x43  # 'C'
_EVENT_ERROR_BYTE: Final = 0x45  # 'E'

# Endpoint byte: direction in bit 7, endpoint number in the low nibble.
_ENDPOINT_DIR_MASK: Final = 0x80
_ENDPOINT_NUM_MASK: Final = 0x0F

# flag_setup byte: 0 means the 8-byte setup field is valid.
_FLAG_SETUP_PRESENT: Final = 0x00

# struct.unpack format string for the 48-byte basic header. Little-endian,
# no padding — matches the kernel's on-wire layout exactly.
_BASIC_HEADER_FORMAT: Final = "<QBBBBHBBqiiII8s"

# Explicit shape of the unpacked header tuple, used to give pyright strict
# mode something concrete to type-check against. struct.unpack returns
# tuple[Any, ...] in stubs; this annotation narrows it.
_HeaderTuple = tuple[
    int,  # urb_id
    int,  # event_type byte
    int,  # xfer_type byte
    int,  # epnum
    int,  # devnum
    int,  # busnum
    int,  # flag_setup
    int,  # flag_data (ignored)
    int,  # ts_sec
    int,  # ts_usec
    int,  # status
    int,  # length
    int,  # captured_length
    bytes,  # setup_bytes
]


# --- Errors ---------------------------------------------------------------


class UrbDecodeError(Exception):
    """Base class for all URB-decoder errors."""


class MalformedUsbmonHeaderError(UrbDecodeError):
    """Raised when a usbmon header cannot be parsed.

    Causes include a payload shorter than the declared header size, an
    unrecognized event-type byte, an unrecognized transfer-type byte,
    or a link-type value that does not correspond to either usbmon
    format.
    """


class UnsupportedTransferTypeError(UrbDecodeError):
    """Raised when a URB's transfer type is recognized but out of scope.

    Currently raised for Interrupt (scheduled for Milestone 2) and
    Isochronous (out of scope for this project). The decoder distinguishes
    "I know what this is but won't decode it" from "I don't recognize
    this byte at all" — the latter raises :class:`MalformedUsbmonHeaderError`.
    """


# --- Public dataclasses ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class UrbRecord:
    """One decoded URB event — a single submission, completion, or error record.

    Two :class:`UrbRecord` instances share the same :attr:`urb_id` when
    they describe the same logical URB. :func:`pair_urbs` groups them
    into :class:`UrbTransaction` objects.
    """

    urb_id: int
    event_type: EventType
    transfer_type: TransferType
    direction: Direction
    bus_num: int
    dev_num: int
    endpoint: int
    status: int
    length: int  # reported (full) length of the data phase
    captured_length: int  # bytes actually captured (may be < length)
    data: bytes  # captured data payload
    setup: bytes | None  # 8-byte setup packet; None for non-control records
    timestamp: float  # seconds since epoch, microsecond resolution


@dataclass(frozen=True, slots=True)
class UrbTransaction:
    """A submission paired with its completion (or error) for one URB id.

    Either :attr:`submission` or :attr:`completion` may be ``None`` when
    only one half of a transaction was captured (transactions in flight
    at the start or end of the capture). At least one is always present.
    """

    urb_id: int
    submission: UrbRecord | None
    completion: UrbRecord | None


# --- Decoder --------------------------------------------------------------


def decode_urb(packet_data: bytes, link_type: int) -> UrbRecord:
    """Decode one packet's raw bytes into a :class:`UrbRecord`.

    Parameters
    ----------
    packet_data:
        The full packet payload as it appeared in the pcap-ng block —
        i.e. the usbmon header followed by the captured data.
    link_type:
        Link type of the source interface, taken from the IDB that
        introduced the interface. Must be :data:`LINKTYPE_USB_LINUX`
        or :data:`LINKTYPE_USB_LINUX_MMAPPED`.

    Raises
    ------
    MalformedUsbmonHeaderError
        ``link_type`` is not a usbmon link type, ``packet_data`` is
        shorter than the declared header size, or the header contains
        an unrecognized event-type or transfer-type byte.
    UnsupportedTransferTypeError
        The header declares an Interrupt transfer (Milestone 2) or an
        Isochronous transfer (out of scope).
    """
    header_size = _header_size_for_link_type(link_type)
    if len(packet_data) < header_size:
        raise MalformedUsbmonHeaderError(
            f"payload too short for {header_size}-byte usbmon header: got {len(packet_data)} bytes"
        )

    unpacked: _HeaderTuple = struct.unpack(_BASIC_HEADER_FORMAT, packet_data[:HEADER_SIZE_USB_LINUX])
    (
        urb_id,
        event_byte,
        xfer_byte,
        epnum,
        devnum,
        busnum,
        flag_setup,
        _flag_data,
        ts_sec,
        ts_usec,
        status,
        length,
        captured_length,
        setup_bytes,
    ) = unpacked

    event_type = _decode_event_type(event_byte)
    transfer_type = _decode_transfer_type(xfer_byte)

    direction: Direction = "in" if epnum & _ENDPOINT_DIR_MASK else "out"
    endpoint = epnum & _ENDPOINT_NUM_MASK

    setup: bytes | None = setup_bytes if transfer_type == "control" and flag_setup == _FLAG_SETUP_PRESENT else None

    data = packet_data[header_size : header_size + captured_length]

    return UrbRecord(
        urb_id=urb_id,
        event_type=event_type,
        transfer_type=transfer_type,
        direction=direction,
        bus_num=busnum,
        dev_num=devnum,
        endpoint=endpoint,
        status=status,
        length=length,
        captured_length=captured_length,
        data=data,
        setup=setup,
        timestamp=ts_sec + ts_usec / 1_000_000.0,
    )


def _header_size_for_link_type(link_type: int) -> int:
    """Return the on-wire header size for a usbmon link type."""
    if link_type == LINKTYPE_USB_LINUX_MMAPPED:
        return HEADER_SIZE_USB_LINUX_MMAPPED
    if link_type == LINKTYPE_USB_LINUX:
        return HEADER_SIZE_USB_LINUX
    raise MalformedUsbmonHeaderError(
        f"link type {link_type} is not a usbmon link type ({LINKTYPE_USB_LINUX} or {LINKTYPE_USB_LINUX_MMAPPED})"
    )


def _decode_event_type(byte: int) -> EventType:
    """Project a raw event byte into a typed :data:`EventType` literal."""
    if byte == _EVENT_SUBMIT_BYTE:
        return "submission"
    if byte == _EVENT_COMPLETE_BYTE:
        return "completion"
    if byte == _EVENT_ERROR_BYTE:
        return "error"
    raise MalformedUsbmonHeaderError(f"unknown usbmon event-type byte: {byte:#04x}")


def _decode_transfer_type(byte: int) -> TransferType:
    """Project a raw transfer-type byte into a typed :data:`TransferType`.

    Raises :class:`UnsupportedTransferTypeError` for Interrupt and
    Isochronous (recognized but out of scope), and
    :class:`MalformedUsbmonHeaderError` for any other byte value.
    """
    if byte == _XFER_CONTROL:
        return "control"
    if byte == _XFER_BULK:
        return "bulk"
    if byte == _XFER_INTERRUPT:
        raise UnsupportedTransferTypeError(
            "interrupt transfers are scheduled for Milestone 2 and are not yet supported"
        )
    if byte == _XFER_ISOCHRONOUS:
        raise UnsupportedTransferTypeError("isochronous transfers are out of scope for this project")
    raise MalformedUsbmonHeaderError(f"unknown usbmon transfer-type byte: {byte:#04x}")


# --- Pairing --------------------------------------------------------------


def pair_urbs(records: Iterable[UrbRecord]) -> Iterator[UrbTransaction]:
    """Group URB records into submit/complete transactions by URB id.

    Walks the input stream in capture order. As completion or error
    records arrive, they are paired with the previously seen submission
    of the same URB id and yielded as a :class:`UrbTransaction`. After
    the input is exhausted, any submissions still without a matching
    completion are yielded as transactions with ``completion=None``
    (transactions in flight when the capture ended).

    Edge cases the function handles deliberately:

    * **Orphan completions** — a completion or error record whose
      matching submission was not seen, typically because the capture
      started mid-transaction. Yielded with ``submission=None``.
    * **Orphan submissions at end** — yielded with ``completion=None``
      after the input is exhausted, in insertion order.
    * **Double submission for one URB id without an intervening
      completion** — anomalous but observed in some captures. The earlier
      submission is yielded immediately as an orphan
      (``completion=None``) before the new submission replaces it in the
      pending set. This surfaces the anomaly rather than silently
      dropping data.
    """
    pending: dict[int, UrbRecord] = {}
    for record in records:
        if record.event_type == "submission":
            previous = pending.get(record.urb_id)
            if previous is not None:
                yield UrbTransaction(
                    urb_id=previous.urb_id,
                    submission=previous,
                    completion=None,
                )
            pending[record.urb_id] = record
            continue
        submission = pending.pop(record.urb_id, None)
        yield UrbTransaction(
            urb_id=record.urb_id,
            submission=submission,
            completion=record,
        )
    for urb_id, submission in pending.items():
        yield UrbTransaction(urb_id=urb_id, submission=submission, completion=None)
