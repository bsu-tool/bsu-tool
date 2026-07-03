"""Raw event source for Linux usbmon character devices.

Wraps ``/dev/usbmonN`` for one USB bus and yields ``(header, data)``
tuples of raw bytes — one per URB event delivered by the kernel.
Does no parsing, no filtering by transfer type, and no pcap-ng
encoding; those are upper layers' concerns.

Three behaviors worth understanding before reading the code:

1. **Filler packets are dropped here.** The kernel emits events with
   ``event_type == 0x40`` ('@') as ring-buffer slot padding. They are
   not real URBs and would fail to decode downstream. This module is
   the single gatekeeper that drops them.

2. **Iteration blocks but is interruptible.** Each ``__next__`` waits
   up to ``poll_timeout_ms`` for the kernel to produce an event. If
   the caller's ``stop_event`` is set during a wait, iteration stops
   cleanly at the next timeout boundary — so worst-case stop latency
   is bounded by ``poll_timeout_ms`` regardless of bus activity.

3. **Errors are mapped to typed exceptions at open time.** A missing
   device node (common on WSL2 where bus numbers shift between
   reboots) raises :class:`UsbmonBusNotAvailableError` with a hint
   about which buses *are* available. Permission failures raise
   :class:`UsbmonPermissionError` with the conventional fix.

The kernel-side ABI is documented in ``Documentation/usb/usbmon.rst``
in the Linux source tree. The relevant pieces:

* ``MON_IOCX_GETX`` (ioctl request ``_IOW(0x92, 10, struct mon_get_arg)``)
  fetches one event, copying 64 bytes of header into ``hdr`` and up to
  ``alloc`` bytes of captured data into ``data``. Returns 0 on success
  or sets errno on failure (EINTR is the common non-fatal case).
* ``struct mon_get_arg { struct mon_bin_hdr *hdr; void *data; size_t alloc; }``
  — three pointer/size_t fields, native alignment.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import select
import threading
from pathlib import Path
from types import TracebackType
from typing import Final

# ---------------------------------------------------------------------------
# Constants — usbmon ABI
# ---------------------------------------------------------------------------

#: Header size returned by MON_IOCX_GETX. Matches struct mon_bin_hdr in
#: the kernel; also matches HEADER_SIZE_USB_LINUX_MMAPPED in urb_decoder.
_HEADER_SIZE: Final = 64

#: Maximum captured data per event. 65535 matches tshark's snap-len
#: default and is larger than any single USB transfer we expect.
_DATA_BUFFER_SIZE: Final = 65535

#: usbmon event-type byte for ring-buffer filler. Real events use
#: 0x53/0x43/0x45 ('S'/'C'/'E'). Anything else is junk to be dropped.
_FILLER_EVENT_BYTE: Final = 0x40  # '@'

#: Offset of the event-type byte within the header.
_EVENT_TYPE_OFFSET: Final = 8

# ---------------------------------------------------------------------------
# Constants — ioctl encoding
# ---------------------------------------------------------------------------
#
# Linux ioctl request numbers pack direction, type, command, and size
# into a 32-bit integer. The encoding (from include/uapi/asm-generic/ioctl.h):
#
#     bits 31-30: direction (00 none, 01 write, 10 read, 11 read/write)
#     bits 29-16: argument size in bytes
#     bits 15-8:  type ("magic" byte, 0x92 for usbmon)
#     bits 7-0:   command number
#
# MON_IOCX_GETX is defined as _IOW(MON_IOC_MAGIC, 10, struct mon_get_arg).
# _IOW means direction=01 (write: userspace → kernel passes the arg).
# The size is sizeof(struct mon_get_arg), which on 64-bit Linux is 24
# bytes (two pointers + size_t).

_IOC_NRBITS: Final = 8
_IOC_TYPEBITS: Final = 8
_IOC_SIZEBITS: Final = 14

_IOC_NRSHIFT: Final = 0
_IOC_TYPESHIFT: Final = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT: Final = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT: Final = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_WRITE: Final = 1

_MON_IOC_MAGIC: Final = 0x92
_MON_IOCX_GETX_NR: Final = 10


class _MonGetArg(ctypes.Structure):
    """ctypes layout of ``struct mon_get_arg``.

    Field order and types must match the kernel's UAPI header exactly.
    On 64-bit Linux, ``c_void_p`` is 8 bytes and ``c_size_t`` is 8 bytes,
    giving a struct size of 24 bytes — which is what gets encoded into
    the ioctl request number.
    """

    _fields_ = [
        ("hdr", ctypes.c_void_p),
        ("data", ctypes.c_void_p),
        ("alloc", ctypes.c_size_t),
    ]


def _ioc(direction: int, magic: int, nr: int, size: int) -> int:
    """Encode an ioctl request number — the Python equivalent of _IOC()."""
    return (direction << _IOC_DIRSHIFT) | (magic << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)


_MON_IOCX_GETX: Final = _ioc(
    direction=_IOC_WRITE,
    magic=_MON_IOC_MAGIC,
    nr=_MON_IOCX_GETX_NR,
    size=ctypes.sizeof(_MonGetArg),
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class UsbmonError(Exception):
    """Base class for all usbmon source errors."""


class UsbmonBusNotAvailableError(UsbmonError):
    """Raised when ``/dev/usbmonN`` does not exist for the requested bus.

    On WSL2 and other dynamic environments, bus numbers can shift between
    reboots or when devices are attached/detached. The error message
    includes the list of currently-available bus numbers as a hint.
    """


class UsbmonPermissionError(UsbmonError):
    """Raised when the user lacks permission to open ``/dev/usbmonN``.

    The device is conventionally owned by ``root:usbmon`` with mode 0640;
    fix by running as root or by adding the user to the ``usbmon`` group.
    """


class UsbmonIoctlError(UsbmonError):
    """Raised when ``MON_IOCX_GETX`` fails with an unrecoverable error.

    EINTR is handled internally and does not surface as this exception;
    anything else (typically ENODEV when the bus disappears mid-capture)
    does.
    """


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class UsbmonSource:
    """Iterable over raw events from one usbmon character device.

    Use as a context manager so the underlying file descriptor is closed
    on exit::

        with UsbmonSource(bus_number=3, stop_event=stop) as source:
            for header, data in source:
                ...

    Each iteration of ``__next__`` blocks for up to ``poll_timeout_ms``
    waiting for an event. If ``stop_event`` is set during a wait, the
    iterator raises ``StopIteration`` at the next timeout boundary —
    so worst-case stop latency is bounded by ``poll_timeout_ms``
    regardless of bus traffic.

    Filler events (kernel ring-buffer padding) are silently dropped;
    they are not real URBs.
    """

    __slots__ = (
        "_bus_number",
        "_data_buf",
        "_data_ptr",
        "_device_path",
        "_fd",
        "_hdr_buf",
        "_hdr_ptr",
        "_poll_timeout_ms",
        "_poller",
        "_stop_event",
    )

    def __init__(
        self,
        bus_number: int,
        *,
        stop_event: threading.Event,
        poll_timeout_ms: int = 100,
    ) -> None:
        self._bus_number = bus_number
        self._device_path = Path(f"/dev/usbmon{bus_number}")
        self._stop_event = stop_event
        self._poll_timeout_ms = poll_timeout_ms

        # File descriptor is opened in __enter__, not __init__. Construct-
        # ing a source object should not have system-level side effects.
        self._fd: int | None = None
        self._poller: select.poll | None = None

        # Persistent ctypes buffers — allocated once, reused for every
        # ioctl call. The kernel writes into these buffers each call;
        # we copy out the bytes we care about and hand the buffers
        # back to the kernel on the next iteration.
        self._hdr_buf = (ctypes.c_ubyte * _HEADER_SIZE)()
        self._data_buf = (ctypes.c_ubyte * _DATA_BUFFER_SIZE)()
        self._hdr_ptr = ctypes.cast(self._hdr_buf, ctypes.c_void_p)
        self._data_ptr = ctypes.cast(self._data_buf, ctypes.c_void_p)

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> UsbmonSource:
        try:
            self._fd = os.open(str(self._device_path), os.O_RDONLY)
        except FileNotFoundError as exc:
            raise UsbmonBusNotAvailableError(self._not_available_message()) from exc
        except PermissionError as exc:
            raise UsbmonPermissionError(
                f"permission denied opening {self._device_path}; run as root or add user to the 'usbmon' group"
            ) from exc

        self._poller = select.poll()
        self._poller.register(self._fd, select.POLLIN)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._poller = None

    # -- iteration ---------------------------------------------------------

    def __iter__(self) -> UsbmonSource:
        return self

    def __next__(self) -> tuple[bytes, bytes]:
        if self._fd is None or self._poller is None:
            raise RuntimeError("UsbmonSource must be used as a context manager")

        while True:
            if self._stop_event.is_set():
                raise StopIteration

            # poll() may itself be interrupted by EINTR; treat that as
            # "wake up and check the stop flag", same as a timeout.
            try:
                ready = self._poller.poll(self._poll_timeout_ms)
            except InterruptedError:
                continue

            if not ready:
                # Timeout. Loop back to check the stop flag.
                continue

            event = self._fetch_event()
            if event is None:
                # Filler packet or EINTR during ioctl. Loop again.
                continue
            return event

    # -- internals ---------------------------------------------------------

    def _fetch_event(self) -> tuple[bytes, bytes] | None:
        """Issue one MON_IOCX_GETX ioctl and return its bytes, or None.

        Returns None for filler packets (drop and retry) and for EINTR
        (caller's stop-flag check will pick up Ctrl+C on the next loop).
        Any other ioctl failure raises :class:`UsbmonIoctlError`.
        """
        assert self._fd is not None  # invariant: only called between __enter__/__exit__

        arg = _MonGetArg(
            hdr=self._hdr_ptr,
            data=self._data_ptr,
            alloc=_DATA_BUFFER_SIZE,
        )

        try:
            fcntl.ioctl(self._fd, _MON_IOCX_GETX, arg)
        except InterruptedError:
            return None
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return None
            raise UsbmonIoctlError(
                f"MON_IOCX_GETX failed on {self._device_path}: {os.strerror(exc.errno) if exc.errno else exc}"
            ) from exc

        # Drop ring-buffer filler events. These are not real URBs and
        # would fail to decode downstream.
        if self._hdr_buf[_EVENT_TYPE_OFFSET] == _FILLER_EVENT_BYTE:
            return None

        header_bytes = bytes(self._hdr_buf)
        # The kernel populates `len_cap` (bytes 36-39 of the header) with
        # the actual captured data length. Slice the data buffer to that
        # length so callers never see uninitialized tail bytes from
        # earlier events.
        len_cap = int.from_bytes(header_bytes[36:40], "little", signed=False)
        captured = min(len_cap, _DATA_BUFFER_SIZE)
        data_bytes = bytes(self._data_buf[:captured])

        return header_bytes, data_bytes

    # -- error helpers -----------------------------------------------------

    def _not_available_message(self) -> str:
        available = _list_available_buses()
        if not available:
            return (
                f"usbmon bus {self._bus_number} not available "
                f"({self._device_path} does not exist). "
                f"No /dev/usbmon* devices found — is the usbmon module loaded?"
            )
        return (
            f"usbmon bus {self._bus_number} not available "
            f"({self._device_path} does not exist). "
            f"Available buses: {', '.join(str(n) for n in available)}."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_available_buses() -> list[int]:
    """Return sorted list of bus numbers with a /dev/usbmonN device node.

    Used to make the "bus not found" error message actually useful.
    Returns an empty list if /dev doesn't exist or no usbmon nodes are
    present (which usually means the usbmon kernel module isn't loaded).
    """
    buses: list[int] = []
    try:
        for entry in Path("/dev").iterdir():
            name = entry.name
            if not name.startswith("usbmon"):
                continue
            suffix = name[len("usbmon") :]
            if suffix.isdigit():
                buses.append(int(suffix))
    except (FileNotFoundError, PermissionError):
        return []
    return sorted(buses)


__all__ = [
    "UsbmonBusNotAvailableError",
    "UsbmonError",
    "UsbmonIoctlError",
    "UsbmonPermissionError",
    "UsbmonSource",
]
